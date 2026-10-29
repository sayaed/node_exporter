// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux && !nouserdiskinfo
// +build linux,!nouserdiskinfo

package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec" //nolint:depguard // deliberate, documented exception to the no-os/exec rule in AGENTS.md; see userdiskRun.
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	userdiskInfoSubsystem = "user_use_disk"

	// maxUserdiskWorkers caps how many `du` processes run at once. The actual
	// fan-out is min(NumCPU, maxUserdiskWorkers, number of home directories),
	// so a machine with fewer cores gets a proportionally narrower one.
	//
	// The cap exists for the top end, not the bottom: du is I/O bound, and
	// past a few dozen concurrent walks of the same filesystem the extra
	// processes only deepen the I/O queue for everything else sharing the
	// disk. 32 keeps a 128-core host from handing the filesystem far more work
	// than a hundred home directories could ever benefit from.
	maxUserdiskWorkers = 32

	// userdiskRefreshInterval is how often the background pass re-measures the
	// home directories. Deliberately a constant rather than a flag: nothing
	// about the metric set depends on it, so it only has to be small enough to
	// keep cache_age_seconds meaningful.
	userdiskRefreshInterval = 5 * time.Minute

	// userdiskRefreshTimeout caps one background pass end to end, so a stuck du
	// cannot leave the refresher looping forever without ever publishing. A
	// pass that runs out of time is abandoned, and the directories it never
	// reached keep the values they already had.
	userdiskRefreshTimeout = 5 * time.Minute

	// userdiskStaleAfter is how long one directory may keep its previous
	// measurement before it stops being reported at all.
	//
	// Without it a directory whose du keeps failing -- no permission, or
	// permanently last in a queue that always runs out of time -- would be
	// carried forward forever, while cache_age_seconds kept resetting on every
	// pass and showed nothing wrong. The figure for that user would silently
	// freeze and no panel would say so. Dropping the series instead turns the
	// failure into a visible gap. Three intervals covers the worst case of one
	// aborted pass plus the sleep that follows it.
	userdiskStaleAfter = 3 * userdiskRefreshInterval

	// userdiskSudoProbeTimeout bounds the one-off `sudo -n du --version` probe.
	//
	// The probe runs inside a sync.Once, so an unbounded one -- which is what
	// context.Background() gave it -- would not merely be slow: it would block
	// the first background measurement pass forever, and through it the
	// publication of every figure, with no timeout anywhere above to cut it
	// short. Ten seconds is far past the point where a working -n sudo has
	// answered, and a sudo that has to prompt is exactly the case that must be
	// given up on instead of waited for.
	userdiskSudoProbeTimeout = 10 * time.Second
)

var userDiskLabelNames = []string{"username", "pwd", "env"}

type userdiskCollector struct {
	sizeDesc    *prometheus.Desc
	ageDesc     *prometheus.Desc
	refreshDesc *prometheus.Desc
	logger      *slog.Logger
}

// 定义标签结构体
type userdiskLabels struct {
	username, pwd, env string
}

// userdiskCache is the result of one background pass over the home
// directories. It is published as a whole and never mutated afterwards, so
// readers only need the RWMutex to swap the pointer safely.
type userdiskCache struct {
	sizes    map[string]userdiskDirStat // home directory -> size and its measurement time
	taken    time.Time                  // when this pass finished
	duration time.Duration
}

var (
	userdiskCacheMu   sync.RWMutex
	userdiskCacheData *userdiskCache
	userdiskOnce      sync.Once
)

func init() {
	registerCollector("userdiskinfo", defaultEnabled, NewUserdiskCollector)
}

func NewUserdiskCollector(logger *slog.Logger) (Collector, error) {
	sizeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userdiskInfoSubsystem, "total"),
		"Disk usage by user in bytes, measured out of band.",
		userDiskLabelNames, nil,
	)
	ageDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userdiskInfoSubsystem, "cache_age_seconds"),
		"Age of the disk usage figures currently being served, in seconds. Keeps growing if the background measurement cannot complete.",
		nil, nil,
	)
	refreshDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userdiskInfoSubsystem, "cache_refresh_duration_seconds"),
		"Wall clock time of the last successful background disk usage pass, in seconds.",
		nil, nil,
	)

	startUserdiskRefresher(logger)

	return &userdiskCollector{
		sizeDesc:    sizeDesc,
		ageDesc:     ageDesc,
		refreshDesc: refreshDesc,
		logger:      logger,
	}, nil
}

func (c *userdiskCollector) Update(ch chan<- prometheus.Metric) error {
	labels, err := parseUserDiskLabels()
	if err != nil {
		return err
	}

	cache := getUserdiskCache()
	if cache == nil {
		// The first background pass has not finished yet. This is the whole
		// point of the design: the scrape returns immediately instead of
		// waiting on du, and the metrics appear once the pass completes.
		c.logger.Debug("Home directory sizes not measured yet, skipping")
		return nil
	}

	emitted := 0
	scrapeTime := time.Now()
	for _, l := range labels {
		stat, ok := cache.sizes[l.pwd]
		if !ok {
			// Never measured at all: no pass has reached this directory yet.
			// Reporting nothing is right -- there is no figure to report, and
			// cache_age_seconds says how far the background pass is behind.
			continue
		}
		// A measured zero is reported like any other figure.
		// userdiskDirectorySize measures a home directory that no longer
		// exists as 0 on purpose, so that it stops being carried over. If the
		// zero were filtered out here as well, "this directory is gone" would
		// become a series that silently disappears -- which no alert can
		// distinguish from the exporter itself being down. A directory that
		// could not be measured never reaches this line with a zero: the
		// background pass stores a figure only on success, and keeps the
		// previous one otherwise.
		//
		// A figure that has gone too long without a re-measurement is the
		// other case, and *is* dropped below. Carrying a stale figure forward
		// would make it indistinguishable from a fresh one on the dashboard,
		// while a missing series is a signal an alert can act on.
		if stat.stale(scrapeTime, userdiskStaleAfter) {
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			c.sizeDesc, prometheus.GaugeValue, float64(stat.size), l.username, l.pwd, l.env,
		)
		emitted++
	}

	// Make staleness observable: without these two, a background pass that
	// stopped working would be indistinguishable from a machine where nobody
	// uses any disk. Alert on `cache_age_seconds` exceeding a few intervals.
	ch <- prometheus.MustNewConstMetric(
		c.ageDesc, prometheus.GaugeValue, time.Since(cache.taken).Seconds(),
	)
	ch <- prometheus.MustNewConstMetric(
		c.refreshDesc, prometheus.GaugeValue, cache.duration.Seconds(),
	)

	c.logger.Debug("Disk usage served from cache",
		"stats_count", emitted, "age", time.Since(cache.taken), "refresh_duration", cache.duration)
	return nil
}

// startUserdiskRefresher launches the single background goroutine that keeps
// the home directory sizes up to date.
//
// `du` costs O(files), so on a large or slow home directory a single call can
// take tens of seconds -- incompatible with running inside a scrape, because
// /metrics is encoded and written only once every collector has returned: one
// slow collector makes the entire scrape miss its deadline. Measuring out of
// band decouples scrape latency from directory size entirely.
func startUserdiskRefresher(logger *slog.Logger) {
	userdiskOnce.Do(func() {
		go func() {
			for {
				if cache, err := measureUserdiskSizes(logger); err != nil {
					// Keep serving the previous figures rather than dropping
					// the metrics; cache_age_seconds exposes the staleness.
					logger.Error("Background home directory measurement failed, keeping previous values", "error", err)
				} else {
					userdiskCacheMu.Lock()
					userdiskCacheData = cache
					userdiskCacheMu.Unlock()

					logger.Debug("Background home directory measurement completed",
						"users", len(cache.sizes), "duration", cache.duration)
				}

				// Wait *after* the pass rather than on a fixed tick, so a slow
				// pass can never overlap the next one and pile up du processes.
				time.Sleep(userdiskRefreshInterval)
			}
		}()
	})
}

func getUserdiskCache() *userdiskCache {
	userdiskCacheMu.RLock()
	defer userdiskCacheMu.RUnlock()
	return userdiskCacheData
}

// measureUserdiskSizes runs one full pass over every home directory.
func measureUserdiskSizes(logger *slog.Logger) (*userdiskCache, error) {
	started := time.Now()

	labels, err := parseUserDiskLabels()
	if err != nil {
		return nil, err
	}

	// Every account has its own home directory here, so this is just the set of
	// directories to measure -- deduplicated. Two accounts pointing at the same
	// path (a shared home, or more often both carrying a placeholder such as
	// /nonexistent) would otherwise each start their own du over it, and the
	// second result would do nothing but overwrite the first.
	paths := make([]string, 0, len(labels))
	seen := make(map[string]struct{}, len(labels))
	for _, l := range labels {
		if l.pwd == "" {
			continue
		}
		if _, dup := seen[l.pwd]; dup {
			continue
		}
		seen[l.pwd] = struct{}{}
		paths = append(paths, l.pwd)
	}

	ctx, cancel := context.WithTimeout(context.Background(), userdiskRefreshTimeout)
	defer cancel()

	sizes := make(map[string]userdiskDirStat, len(paths))
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Scale with the core count up to the cap, and never start more workers
	// than there are directories to measure. Core count is a weak signal --
	// du is I/O bound, so it bounds the bookkeeping cost rather than what the
	// filesystem can serve -- but it is the only signal available without
	// measuring a pass first, and the cap keeps it from doing harm.
	workers := min(max(runtime.NumCPU(), 1), maxUserdiskWorkers, len(paths))

	jobs := make(chan string)
	for range workers {
		wg.Go(func() {
			for path := range jobs {
				size, err := userdiskDirectorySize(ctx, path)
				if err != nil {
					logger.Debug("Home directory measurement failed, keeping the previous value",
						"path", path, "error", err)
					continue
				}
				measured := time.Now()
				mu.Lock()
				sizes[path] = userdiskDirStat{size: size, taken: measured}
				mu.Unlock()
			}
		})
	}

	// Feed the workers until every directory is queued or the pass runs out of
	// time. Whatever is not reached keeps its previous value below, so a
	// degraded pass costs freshness instead of making metrics disappear.
feed:
	for i, path := range paths {
		select {
		case jobs <- path:
		case <-ctx.Done():
			logger.Warn("Home directory measurement hit its timeout, keeping previous values for the rest",
				"timeout", userdiskRefreshTimeout, "queued", i, "total", len(paths))
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	// Carry over the directories this pass did not reach, timestamp included:
	// the age of each figure travels with it, so Update() knows which ones have
	// gone stale rather than seeing a pass that always looks fresh.
	if previous := getUserdiskCache(); previous != nil {
		for path, stat := range previous.sizes {
			if _, refreshed := sizes[path]; !refreshed {
				sizes[path] = stat
			}
		}
	}

	// Report the frozen ones once per pass rather than on every scrape: a
	// series that quietly disappears from the output is easy to miss.
	if stale := staleUserdiskPaths(sizes, userdiskStaleAfter); len(stale) > 0 {
		slices.Sort(stale)
		logger.Warn("Home directories not measured successfully for a long time are no longer reported",
			"count", len(stale), "stale_after", userdiskStaleAfter,
			"example", strings.Join(stale[:min(3, len(stale))], ", "))
	}

	return &userdiskCache{
		sizes:    sizes,
		taken:    time.Now(),
		duration: time.Since(started),
	}, nil
}

// userdiskDirectorySize returns the apparent size of path in bytes: the number
// `du -sbH` prints.
func userdiskDirectorySize(ctx context.Context, path string) (int64, error) {
	// Stat follows a symlink, so a home directory that is one is measured as
	// the directory it points at rather than as the link.
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Gone: report zero rather than an error so the stale entry is
			// cleared from the cache instead of being carried over forever.
			return 0, nil
		}
		return 0, err
	}

	if !info.IsDir() {
		return info.Size(), nil
	}

	// -H (--dereference-args) is what makes a home directory that is itself a
	// symlink report the size of its target. Without it GNU du follows
	// -P/--no-dereference by default, so /home/jdoe -> /data/jdoe would be
	// measured as the length of the link itself (a few bytes) rather than as
	// the directory behind it. -H only affects the operand named on the
	// command line; symlinks *inside* the tree are still not followed, which
	// is what keeps a link loop from being walked forever.
	argv := []string{"du", "-sbH", "--", path}
	if userdiskUseSudo() {
		argv = append([]string{"sudo", "-n"}, argv...)
	}

	output, err := userdiskRun(ctx, argv...)
	if err != nil {
		return 0, fmt.Errorf("failed to measure %s: %w", path, err)
	}

	// du -sb prints "<size>\t<path>".
	sizeField, _, _ := strings.Cut(string(output), "\t")
	size, err := strconv.ParseInt(strings.TrimSpace(sizeField), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse du output %q: %w", strings.TrimSpace(string(output)), err)
	}

	return size, nil
}

// userdiskRun executes argv without a shell.
//
// This is the only place that starts a subprocess, and it is here on purpose:
// du is the one way to total a home directory whose contents the exporter may
// not be able to read itself when it runs unprivileged, which is the normal
// case. It is reached exclusively from the background refresher above -- never
// from a scrape -- and always through a context with a hard timeout, so it
// cannot stall /metrics.
func userdiskRun(ctx context.Context, argv ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)

	output, err := cmd.Output()
	if err != nil {
		// A failing du explains itself on stderr ("cannot read directory ...
		// Permission denied"), and that is the usual reason a user's metric
		// goes missing, so carry the message into the error instead of
		// reporting a bare "exit status 1".
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if stderr := strings.TrimSpace(string(exitErr.Stderr)); stderr != "" {
				return output, fmt.Errorf("%w: %s", err, stderr)
			}
		}
		return output, err
	}

	return output, nil
}

var (
	userdiskSudoOnce sync.Once
	userdiskSudoOK   bool
)

// userdiskUseSudo reports whether `du` may be run through sudo.
//
// Probed once, non-interactively. A non-root exporter can only see the size of
// the parts of a home directory it is allowed to traverse, so sudo is what
// makes the unreadable remainder visible.
func userdiskUseSudo() bool {
	userdiskSudoOnce.Do(func() {
		if os.Geteuid() == 0 {
			// Already root; sudo would add nothing but a dependency.
			return
		}
		// -n mirrors the flag used by the real invocation: if sudo would need
		// a password we must not wait for one.
		//
		// The probe carries its own deadline rather than running on
		// context.Background(): this Once runs on the background refresher's
		// goroutine, and a sudo that hangs -- waiting on a tty, on an NSS or
		// LDAP lookup, on a file lock -- would otherwise stop that goroutine
		// from ever publishing a measurement.
		ctx, cancel := context.WithTimeout(context.Background(), userdiskSudoProbeTimeout)
		defer cancel()

		_, err := userdiskRun(ctx, "sudo", "-n", "du", "--version")
		userdiskSudoOK = err == nil
	})

	return userdiskSudoOK
}

func parseUserDiskLabels() ([]userdiskLabels, error) {
	users, err := parsePasswdFile()
	if err != nil {
		return nil, err
	}

	// The username from /etc/passwd is already the account name, so the
	// os/user.Lookup loop that used to run here just re-resolved every account
	// through NSS on every scrape to produce the same string. That is one
	// lookup per user per scrape, on the hot path, for nothing.
	//
	// Duplicate label sets are dropped. A passwd file with two lines carrying
	// the same account name -- a hand-edit, or an entry a failed useradd left
	// behind -- produces two identical {username, pwd, env} triples, and
	// prometheus.Gather rejects the whole registry when it meets a metric
	// "collected before with the same name and label values": the entire
	// /metrics endpoint answers HTTP 500, not just this collector. env is
	// derived from username alone, so it cannot tell the two lines apart.
	var usernames []userdiskLabels
	seen := make(map[userdiskLabels]struct{}, len(users))
	for _, u := range users {
		if !isValidShell(u.Shell) {
			continue
		}
		labels := userdiskLabels{
			username: u.Username,
			pwd:      u.HomeDir,
			env:      parseUserEnv(u.Username),
		}
		if _, dup := seen[labels]; dup {
			continue
		}
		seen[labels] = struct{}{}
		usernames = append(usernames, labels)
	}

	return usernames, nil
}

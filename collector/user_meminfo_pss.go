// Copyright 2026 The Prometheus Authors
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

//go:build linux && !nousermeminfo
// +build linux,!nousermeminfo

package collector

import (
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

const (
	userPSSRefreshInterval = time.Minute
	// userPSSMaxInterval caps the adaptive backoff. A measurement that cannot
	// finish within ten minutes is telling the operator something the metric
	// pss_cache_age_seconds also shows; pacing past this point would only
	// hide it.
	userPSSMaxInterval = 10 * time.Minute
	maxUserPSSWorkers  = 4
)

var (
	// userPSSMinRSSKB skips the smaps read of processes too small to be worth
	// it. A process under the threshold contributes less PSS than the read of
	// its own smaps_rollup costs; on a host with thousands of short-lived or
	// container processes that is the difference between a background loop
	// that stays invisible and one that keeps the machine's page cache warm.
	//
	// Users whose processes are all skipped still emit their series -- with a
	// zero PSS -- so skipping cannot punch holes into a dashboard; see the
	// emission in usermeminfo's Update.
	userPSSMinRSSKB = kingpin.Flag(
		"collector.usermeminfo.pss-min-rss-kb",
		"Skip the smaps read for processes whose RSS is below this many KiB; they contribute 0 to their user's PSS. 0 measures every process.",
	).Default("8192").Int()

	// userPSSBudget bounds one background measurement. Reading smaps_rollup
	// takes the target's mmap_lock, so in the minutes after a memory stress
	// test ends -- the reclaim and swap-in storm -- a full pass over every
	// pid can take minutes and feed the very storm it is measuring. An
	// over-budget run stops early and reports partial data; the next run
	// gets a fresh budget and the adaptive interval below keeps the loop
	// from running back-to-back.
	userPSSBudget = kingpin.Flag(
		"collector.usermeminfo.pss-budget",
		"Max wall time for one background PSS measurement; an over-budget run stops early and reports partial data.",
	).Default("60s").Duration()
)

type userPSSStat struct {
	username         string
	env              string
	pssKB            uint64
	unavailableProcs int
}

type userPSSSnapshot struct {
	taken    time.Time
	duration time.Duration
	partial  bool
	users    []userPSSStat
}

var (
	userPSSSnapshotMu   sync.RWMutex
	userPSSSnapshotData *userPSSSnapshot
	userPSSOnce         sync.Once
)

func startUserPSSRefresher(logger *slog.Logger) {
	userPSSOnce.Do(func() {
		go func() {
			interval := userPSSRefreshInterval
			for {
				started := time.Now()
				snapshot, err := measureUserPSS()
				if err != nil {
					logger.Error("Background per-user PSS measurement failed, keeping previous values", "error", err)
				} else {
					userPSSSnapshotMu.Lock()
					userPSSSnapshotData = snapshot
					userPSSSnapshotMu.Unlock()

					if snapshot.partial {
						logger.Warn("Background per-user PSS measurement stopped early on its time budget; values are partial",
							"duration", snapshot.duration)
					}
					logger.Debug("Background per-user PSS measurement completed",
						"users", len(snapshot.users), "duration", snapshot.duration)
				}

				// Adaptive pacing. The old loop slept a fixed minute after
				// finishing, so a measurement that took minutes ran almost
				// back-to-back: exactly when the machine can least afford
				// it. A run that eats two thirds of the interval doubles the
				// next interval; one that gets cheap again walks it back.
				if duration := time.Since(started); duration > interval*2/3 && interval < userPSSMaxInterval {
					interval = min(interval*2, userPSSMaxInterval)
					logger.Warn("PSS measurement is slow relative to its interval; backing off",
						"measurement", duration, "next_interval", interval)
				} else if interval > userPSSRefreshInterval && duration < interval/4 {
					interval = max(interval/2, userPSSRefreshInterval)
				}
				time.Sleep(interval)
			}
		}()
	})
}

func getUserPSSSnapshot() *userPSSSnapshot {
	userPSSSnapshotMu.RLock()
	defer userPSSSnapshotMu.RUnlock()
	return userPSSSnapshotData
}

// measureUserPSS walks the readable processes and sums their PSS per user.
//
// The pid list comes from the latest proc snapshot's RSS hint when there is
// one: it skips both the smaps read and the status read of processes below
// pss-min-rss-kb, and it avoids a second enumeration of /proc right after the
// snapshot walk finished one. Without a hint -- no snapshot yet, or a build
// that ran out of its budget -- the measurement falls back to listing /proc
// itself and measuring every readable pid, the behaviour before the hint
// existed.
//
// deadline stops the measurement in place: pids it did not reach are simply
// absent from the snapshot, and partial=true says so. Users it did not reach
// still emit their series with a zero PSS, via the zero-fill in
// usermeminfo's Update, so a storm degrades values instead of punching holes.
func measureUserPSS() (*userPSSSnapshot, error) {
	started := time.Now()
	deadline := started.Add(*userPSSBudget)

	var pids []int
	haveHint := false
	if snap := latestUserProcSnapshot(); snap != nil && snap.rssByPID != nil {
		// An empty list here means every process is below the threshold:
		// that is a valid result, not a reason to fall back to a full scan.
		haveHint = true
		pids = make([]int, 0, len(snap.rssByPID))
		if *userPSSMinRSSKB > 0 {
			for pid, rssKB := range snap.rssByPID {
				if rssKB >= uint64(*userPSSMinRSSKB) {
					pids = append(pids, pid)
				}
			}
		} else {
			for pid := range snap.rssByPID {
				pids = append(pids, pid)
			}
		}
	}
	if !haveHint {
		var err error
		pids, err = listProcPIDs()
		if err != nil {
			return nil, err
		}
	}

	refreshUIDNameMap()

	users := make(map[string]userPSSStat, min(len(pids), userAggregateHint))
	var usersMu sync.Mutex
	var next atomic.Int64
	var wg sync.WaitGroup
	var partial atomic.Bool

	if len(pids) > 0 {
		workers := min(max(runtime.NumCPU(), 1), maxUserPSSWorkers, len(pids))
		for range workers {
			wg.Go(func() {
				var reader procReader
				for {
					i := int(next.Add(1)) - 1
					if i >= len(pids) {
						return
					}
					if time.Now().After(deadline) {
						partial.Store(true)
						return
					}

					username, pssKB, available, ok := reader.readUserPSS(pids[i])
					if !ok {
						continue
					}

					usersMu.Lock()
					user := users[username]
					user.username = username
					user.env = parseUserEnv(username)
					if available {
						user.pssKB += pssKB
					} else {
						user.unavailableProcs++
					}
					users[username] = user
					usersMu.Unlock()
				}
			})
		}
	}
	wg.Wait()

	stats := make([]userPSSStat, 0, len(users))
	for _, user := range users {
		stats = append(stats, user)
	}
	slices.SortFunc(stats, func(a, b userPSSStat) int {
		return strings.Compare(a.username, b.username)
	})

	return &userPSSSnapshot{
		taken:    time.Now(),
		duration: time.Since(started),
		partial:  partial.Load(),
		users:    stats,
	}, nil
}

func (r *procReader) readUserPSS(pid int) (string, uint64, bool, bool) {
	status, err := r.readInto(r.processFile(pid, "/status"))
	if err != nil {
		return "", 0, false, false
	}
	uid, _, ok := parseStatusUIDAndRSS(status)
	if !ok {
		return "", 0, false, false
	}

	username := lookupUsernameID(uid)
	pssKB, available := r.readPSS(pid)
	return username, pssKB, available, true
}

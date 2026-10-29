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

//go:build linux && !nousercoreinfo
// +build linux,!nousercoreinfo

package collector

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	usercoreInfoSubsystem = "user_core_file"

	// maxUserCoreFiles caps how many core files one scrape reports. Core files
	// accumulate without bound, so without a cap a directory that has been
	// collecting them for years would decide the size of every scrape.
	maxUserCoreFiles = 1000
)

// userCoreLabelNames is the label set of node_user_core_file_info, which is
// emitted once per core dump file. The filepath label is deliberate: it is what
// identifies which binary dumped core.
var userCoreLabelNames = []string{"username", "filepath", "env"}

// usercoreLabels identifies one core dump file on disk.
type usercoreLabels struct {
	username string
	filepath string
	env      string
}

// userCoreStats is one core dump file together with the time it was written.
//
// timestamp is a float64 because that is the type prometheus.NewConstMetric
// takes; it carries the modification time in Unix seconds.
type userCoreStats struct {
	labels    usercoreLabels
	timestamp float64
}

type usercoreCollector struct {
	fileDesc *prometheus.Desc
	logger   *slog.Logger
}

func init() {
	registerCollector("usercoreinfo", defaultEnabled, NewUserCoreCollector)
}

func NewUserCoreCollector(logger *slog.Logger) (Collector, error) {
	fileDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usercoreInfoSubsystem, "info"),
		"user core file info.",
		userCoreLabelNames, nil,
	)
	return &usercoreCollector{
		fileDesc: fileDesc,
		logger:   logger,
	}, nil
}

func (c *usercoreCollector) Update(ch chan<- prometheus.Metric) error {
	start := time.Now()
	stats, err := c.GetStats()
	duration := time.Since(start)

	// 记录收集持续时间（仅在调试模式下）
	c.logger.Debug("Core file collection completed", "duration", duration, "stats_count", len(stats))

	if err != nil {
		return err
	}

	// One series per core file, carrying the file's modification time as its
	// value.
	//
	// The value type is GaugeValue because that is what this metric has always
	// carried -- the type is part of what a consumer sees, so it is not free to
	// change. (Note that client_golang's ValueType enum starts with a blank
	// identifier, so GaugeValue is 2, not 1.)
	for _, s := range stats {
		ch <- prometheus.MustNewConstMetric(
			c.fileDesc, prometheus.GaugeValue, s.timestamp,
			s.labels.username, s.labels.filepath, s.labels.env,
		)
	}
	return nil
}

// GetStats lists the core dump files and stats each one exactly once.
//
// The files are read sequentially. A worker pool cannot pay for itself here --
// there are at most maxUserCoreFiles of them and each costs a single stat --
// and the pool that used to live in this function was actively harmful: two
// channels, four goroutines and a 30 second deadline, whose timeout branch
// closed the result channel while the workers were still sending on it. A send
// on a closed channel panics, and a panic in one of those goroutines is not
// recovered anywhere, so a slow core directory could take the whole
// node_exporter process down.
func (c *usercoreCollector) GetStats() ([]userCoreStats, error) {
	dir, pattern, err := parseCorePrefix()
	if err != nil {
		return nil, fmt.Errorf("failed to parse core prefix: %w", err)
	}

	if dir == "" {
		// core_pattern is a bare file name, resolved against the working
		// directory of whichever process crashed, or a pipe handing the dump
		// to a program. Neither leaves anything behind in a directory this
		// collector can name, so there is nothing to report -- not an error.
		return nil, nil
	}
	if dir == "/" {
		// "/core" really does mean the root directory. It is deliberately not
		// scanned: the root of the filesystem holds plenty of regular files
		// that are not core dumps, and nothing in a name can tell them apart
		// from one. A series that never appears is better than a wrong one.
		c.logger.Warn("core_pattern writes core dumps directly into the root directory, which is not scanned", "core_pattern", dir)
		return nil, nil
	}

	// os.ReadDir lists the directory once and returns sorted entries. The
	// filepath.Glob this replaced matched every name against a pattern and then
	// every file was stat'ed a second time further down, so each core file cost
	// two stats instead of one.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read core file directory %s: %w", dir, err)
	}

	// The name filter runs before the cap, not after. A core_pattern names its
	// files with a prefix ("core.%e.%p"), and the directory it points at is
	// otherwise an ordinary one that can hold anything -- a rotated file, a
	// README, an .crash written by another tool. Reporting every regular file
	// found there would attribute those to their owners as core dumps, and
	// capping the raw listing first would let enough of them push the real
	// dumps out of the window entirely.
	//
	// Sorting makes "the first 1000" a stable set -- the same one filepath.Glob
	// used to produce -- rather than whichever 1000 the filesystem hands back.
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		// An empty pattern means core_pattern ended in a slash, naming a
		// directory rather than a file name. The kernel does produce a file in
		// that case, but rather than encode a rule for it here the whole
		// directory is listed, which is what this collector did before the
		// pattern was applied: a filter that is wrong drops real core dumps,
		// and that costs more than listing a file that is not one.
		if pattern != "" {
			matched, err := filepath.Match(pattern, entry.Name())
			if err != nil || !matched {
				continue
			}
		}
		names = append(names, entry.Name())
	}

	if len(names) > maxUserCoreFiles {
		c.logger.Warn("Too many core files, limiting to first 1000", "total", len(names))
		names = names[:maxUserCoreFiles]
	}

	stats := make([]userCoreStats, 0, len(names))
	for _, name := range names {
		filePath := filepath.Join(dir, name)

		// The one stat of this file: it answers the file type, the owner and
		// the modification time together.
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			c.logger.Error("Failed to stat core file", "filepath", filePath, "error", err)
			continue // 忽略无法访问的文件
		}

		// 只处理常规文件
		if !fileInfo.Mode().IsRegular() {
			c.logger.Warn("Core file is not a regular file", "filepath", filePath)
			continue
		}

		// 获取文件所有者信息
		stat, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		// Resolve through the shared UID -> username cache instead of paying one
		// os/user.LookupId (NSS) round trip per core file on every scrape.
		username := lookupUsernameID(stat.Uid)

		stats = append(stats, userCoreStats{
			labels: usercoreLabels{
				username: username,
				filepath: filePath,
				env:      parseUserEnv(username),
			},
			timestamp: float64(fileInfo.ModTime().Unix()),
		})
	}

	return stats, nil
}

// parseCorePrefix reads /proc/sys/kernel/core_pattern and splits it into the
// directory the kernel writes core dumps into and the glob pattern of the names
// it writes there. See corePatternDirAndLeaf for the shapes the file can take.
func parseCorePrefix() (dir, pattern string, err error) {
	// Read per scrape rather than cached: core_pattern is a tunable, and a
	// cached copy would keep pointing at a directory the kernel had already
	// stopped writing to.
	data, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	if err != nil {
		return "", "", fmt.Errorf("failed to read core_pattern: %w", err)
	}

	dir, pattern = corePatternDirAndLeaf(strings.TrimSpace(string(data)))
	return dir, pattern, nil
}

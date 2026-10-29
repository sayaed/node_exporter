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

//go:build linux && !nousercpuinfo
// +build linux,!nousercpuinfo

package collector

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	usercpuInfoSubsystem = "user_cpu"

	// userCPUHZ is the rate at which the kernel counts CPU time in jiffies.
	//
	// USER_HZ is 100 on every Linux architecture. It is part of the kernel
	// ABI, deliberately frozen there so that a userspace binary sees the same
	// clock rate on any machine, and it is what procfs hardcodes as userHZ.
	// Both the utime/stime pair in /proc/<pid>/stat and every counter on the
	// cpu line of /proc/stat are expressed in these ticks, so publishing them
	// under a _seconds_total name without dividing leaves the per-user figure
	// and the system total each exactly 100x too large. The ratio between the
	// two is unaffected either way, which is why this stayed invisible.
	userCPUHZ = 100
)

var userCpuLabelNames = []string{"username", "env"}

func init() {
	registerCollector("usercpuinfo", defaultEnabled, NewUserCpuCollector)
}

// userCpuStats is the CPU time consumed by every process of one user.
type userCpuStats struct {
	username      string
	env           string
	userTotalTime uint64
}

// CombinedStats carries the per-user figures together with the system total
// they have to be related to in order to become a ratio.
//
// Both totals are in clock ticks (USER_HZ), not seconds. They are only ever
// compared against each other here, so they are kept in the kernel's own unit
// and divided by userCPUHZ at the single point where a metric is built.
type CombinedStats struct {
	userStats       []userCpuStats
	systemTotalTime uint64
}

type userCpuCollector struct {
	userDesc        *prometheus.Desc
	systemTotalDesc *prometheus.Desc
	logger          *slog.Logger
}

// NewUserCpuCollector returns a new Collector exposing per-user CPU time.
func NewUserCpuCollector(logger *slog.Logger) (Collector, error) {
	userDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usercpuInfoSubsystem, "process_cpu_seconds_total"),
		"Total user and system CPU time spent in seconds by user processes.",
		userCpuLabelNames, nil,
	)
	systemTotalDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usercpuInfoSubsystem, "system_cpu_seconds_total"),
		"Total user and system CPU time spent in seconds by system.",
		nil, nil,
	)
	return &userCpuCollector{
		userDesc:        userDesc,
		systemTotalDesc: systemTotalDesc,
		logger:          logger,
	}, nil
}

func (c *userCpuCollector) Update(ch chan<- prometheus.Metric) error {
	stats, err := c.GetStats()
	if err != nil {
		return err
	}

	// A zero system total is the "could not be read" case, already logged by
	// GetStats. The per-user series below come from a different file, so a
	// missing denominator must not take them down with it.
	if stats.systemTotalTime > 0 {
		ch <- prometheus.MustNewConstMetric(
			c.systemTotalDesc, prometheus.GaugeValue,
			float64(stats.systemTotalTime)/userCPUHZ,
		)
	}

	for _, s := range stats.userStats {
		ch <- prometheus.MustNewConstMetric(
			c.userDesc, prometheus.GaugeValue,
			float64(s.userTotalTime)/userCPUHZ, s.username, s.env,
		)
	}
	return nil
}

// GetStats turns the per-user totals of the shared snapshot into CPU counters.
//
// The per-process figures were parsed once, while the snapshot was built: it has
// already summed utime + stime per user out of /proc/<pid>/stat and stripped the
// "pid (comm)" prefix safely, so a comm containing spaces cannot shift the field
// indices.
func (c *userCpuCollector) GetStats() (*CombinedStats, error) {
	snapshot, err := getUserProcSnapshot()
	if err != nil {
		return nil, fmt.Errorf("failed to get process snapshot: %w", err)
	}

	// /proc/stat is the denominator of the per-user share, not a per-user
	// figure, and it is a separate file from the one the figures above come
	// out of. So a failure here degrades to a log line and a zero rather than
	// failing the collector: returning the error would drop every per-user
	// series over a file that none of them depend on.
	systemTotalTime, err := getSystemTotalTime()
	if err != nil {
		c.logger.Warn("Failed to read the system CPU total, reporting per-user figures only", "error", err)
	}

	// A projection of the snapshot, already sorted by username, so there is
	// nothing to aggregate and nothing to sort here.
	userStats := make([]userCpuStats, 0, len(snapshot.users))
	for _, agg := range snapshot.users {
		userStats = append(userStats, userCpuStats{
			username:      agg.username,
			env:           agg.env,
			userTotalTime: agg.cpuTicks,
		})
	}

	return &CombinedStats{
		userStats:       userStats,
		systemTotalTime: systemTotalTime,
	}, nil
}

// getSystemTotalTime returns the total CPU time on the aggregate "cpu" line of
// /proc/stat -- pid, comm-free summary of every CPU. The per-user figures above
// are in the same clock ticks, so they can be related to this value.
func getSystemTotalTime() (uint64, error) {
	statBytes, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}

	for off := 0; off < len(statBytes); {
		line, next := nextLine(statBytes, off)
		off = next

		if !bytes.HasPrefix(line, procKeyCPUSummary) {
			continue
		}

		total, ok := parseCPUSummaryTotal(line)
		if !ok {
			return 0, fmt.Errorf("unexpected format in /proc/stat")
		}
		return total, nil
	}

	return 0, fmt.Errorf("cpu line not found in /proc/stat")
}

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

//go:build linux && !nouserprocesses
// +build linux,!nouserprocesses

package collector

import (
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	userProcSubsystem = "user_processes"
)

var userProcLabelNames = []string{"username", "env"}

type userProcLabels struct {
	username string
	env      string
}

type procStat struct {
	labels      userProcLabels
	procCount   float64
	threadCount float64
}

type userProcCollector struct {
	procDesc   *prometheus.Desc
	threadDesc *prometheus.Desc
	logger     *slog.Logger
}

func init() {
	registerCollector("userprocesses", defaultEnabled, NewUserProcCollector)
}

// NewUserProcCollector returns a new Collector exposing user process and thread stats
func NewUserProcCollector(logger *slog.Logger) (Collector, error) {
	procDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userProcSubsystem, "count"),
		"Number of processes owned by user",
		userProcLabelNames, nil,
	)
	threadDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userProcSubsystem, "threads_count"),
		"Number of threads owned by user",
		userProcLabelNames, nil,
	)
	return &userProcCollector{
		procDesc:   procDesc,
		threadDesc: threadDesc,
		logger:     logger,
	}, nil
}

func (c *userProcCollector) Update(ch chan<- prometheus.Metric) error {
	stats, err := c.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get user process stats: %w", err)
	}

	for _, s := range stats {
		ch <- prometheus.MustNewConstMetric(
			c.procDesc, prometheus.GaugeValue,
			s.procCount, s.labels.username, s.labels.env,
		)
		ch <- prometheus.MustNewConstMetric(
			c.threadDesc, prometheus.GaugeValue,
			s.threadCount, s.labels.username, s.labels.env,
		)
	}
	return nil
}

// GetStats turns the per-user totals of the shared snapshot into counts.
//
// Both the process count and the thread count were accumulated while the
// snapshot was built: num_threads is field 20 of /proc/<pid>/stat, so there is
// no need to readdir /proc/<pid>/task for every process.
func (c *userProcCollector) GetStats() ([]procStat, error) {
	snapshot, err := getUserProcSnapshot()
	if err != nil {
		return nil, fmt.Errorf("failed to get process snapshot: %w", err)
	}

	// 转换为返回格式. The rows arrive sorted by username, so the metric output
	// is stable between scrapes without a sort here.
	stats := make([]procStat, 0, len(snapshot.users))
	for _, agg := range snapshot.users {
		stats = append(stats, procStat{
			labels: userProcLabels{
				username: agg.username,
				env:      agg.env,
			},
			procCount:   float64(agg.procs),
			threadCount: float64(agg.threads),
		})
	}

	return stats, nil
}

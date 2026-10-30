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

//go:build linux && !nousermeminfo
// +build linux,!nousermeminfo

package collector

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	usermemInfoSubsystem = "user_use_memory"
)

var userLabelNames = []string{"username", "env"}

type usermemCollector struct {
	userDesc               *prometheus.Desc
	userPSSDesc            *prometheus.Desc
	userPSSUnavailableDesc *prometheus.Desc
	logger                 *slog.Logger
}

type userLabels struct {
	username, env string
}

type userMemStats struct {
	labels                  userLabels
	size                    float64
	pssSize                 float64
	pssUnavailableProcesses float64
}

func init() {
	registerCollector("usermeminfo", defaultEnabled, NewUserMemCollector)
}

func NewUserMemCollector(logger *slog.Logger) (Collector, error) {
	// PSS requires reading smaps data, so only collect it when this collector is
	// enabled.
	userDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "total"),
		"Sum of resident memory (RSS) for processes owned by the user, in bytes. Shared pages are counted for each process.",
		userLabelNames, nil,
	)
	userPSSDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "pss_bytes"),
		"Sum of proportional set size (PSS) for readable processes owned by the user, in bytes.",
		userLabelNames, nil,
	)
	userPSSUnavailableDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "pss_unavailable_processes"),
		"Number of user-owned processes whose proportional set size could not be read.",
		userLabelNames, nil,
	)
	userMemoryPSSReadNeeded.Store(true)
	return &usermemCollector{
		userDesc:               userDesc,
		userPSSDesc:            userPSSDesc,
		userPSSUnavailableDesc: userPSSUnavailableDesc,
		logger:                 logger,
	}, nil
}

// Update calls (*meminfoCollector).getMemInfo to get the platform specific
// memory metrics.
func (c *usermemCollector) Update(ch chan<- prometheus.Metric) error {
	start := time.Now()
	stats, err := c.GetStats()
	duration := time.Since(start)

	// 记录收集持续时间（仅在调试模式下）
	c.logger.Debug("Memory usage collection completed", "duration", duration, "stats_count", len(stats))

	if err != nil {
		return err
	}
	for _, s := range stats {
		ch <- prometheus.MustNewConstMetric(
			c.userDesc, prometheus.GaugeValue,
			s.size, s.labels.username, s.labels.env,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userPSSDesc, prometheus.GaugeValue,
			s.pssSize, s.labels.username, s.labels.env,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userPSSUnavailableDesc, prometheus.GaugeValue,
			s.pssUnavailableProcesses, s.labels.username, s.labels.env,
		)
	}
	return nil
}

// GetStats turns the per-user RSS and PSS totals of the shared snapshot into
// byte counts.
//
// RSS comes from /proc/<pid>/status. PSS comes from smaps_rollup or, on older
// kernels, smaps. Processes whose PSS cannot be read are counted separately so
// the PSS total is visibly partial rather than silently treated as complete.
func (c *usermemCollector) GetStats() ([]userMemStats, error) {
	snapshot, err := getUserProcSnapshot()
	if err != nil {
		return nil, fmt.Errorf("failed to get process snapshot: %w", err)
	}

	// 转换为字节并构建返回结果. The rows arrive sorted by username, so the
	// metric output is stable between scrapes without a sort here.
	stats := make([]userMemStats, 0, len(snapshot.users))
	for _, agg := range snapshot.users {
		stats = append(stats, userMemStats{
			labels: userLabels{
				username: agg.username,
				env:      agg.env,
			},
			size:                    float64(agg.rssKB) * 1024,
			pssSize:                 float64(agg.pssKB) * 1024,
			pssUnavailableProcesses: float64(agg.pssUnavailableProcs),
		})
	}

	return stats, nil
}

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

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	usermemInfoSubsystem = "user_use_memory"
)

var userMemoryPSSEnabled = kingpin.Flag(
	"collector.usermeminfo.pss",
	"Collect per-user proportional set size (PSS) by reading process smaps data in the background.",
).Default("false").Bool()

var userLabelNames = []string{"username", "env"}

type usermemCollector struct {
	userDesc               *prometheus.Desc
	userPSSDesc            *prometheus.Desc
	userPSSUnavailableDesc *prometheus.Desc
	userPSSCacheAgeDesc    *prometheus.Desc
	userPSSDurationDesc    *prometheus.Desc
	snapshotAgeDesc        *prometheus.Desc
	snapshotDurationDesc   *prometheus.Desc
	snapshotProcsDesc      *prometheus.Desc
	snapshotWalksDesc      *prometheus.Desc
	snapshotPartialDesc    *prometheus.Desc
	collectPSS             bool
	logger                 *slog.Logger
}

type userLabels struct {
	username, env string
}

type userMemStats struct {
	labels userLabels
	size   float64
}

func init() {
	registerCollector("usermeminfo", defaultEnabled, NewUserMemCollector)
}

func NewUserMemCollector(logger *slog.Logger) (Collector, error) {
	collectPSS := *userMemoryPSSEnabled
	collector := newUserMemCollector(logger, collectPSS)
	if collectPSS {
		// The PSS refresher skips processes below pss-min-rss-kb, and its
		// skip list comes from the RSS hint the shared snapshot carries.
		userPSSNeedsRSSHint.Store(true)
		startUserPSSRefresher(logger)
	}
	// The shared snapshot feeds every user_* collector, and whichever of them
	// is constructed first starts the background walk that keeps it warm.
	// Constructing any user_* collector without starting it would leave the
	// snapshot frozen after the cold start.
	startUserProcRefresher()
	return collector, nil
}

func newUserMemCollector(logger *slog.Logger, collectPSS bool) *usermemCollector {
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
	userPSSCacheAgeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "pss_cache_age_seconds"),
		"Age of the latest completed background per-user PSS measurement, in seconds.",
		nil, nil,
	)
	userPSSDurationDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "pss_measure_duration_seconds"),
		"Duration of the latest completed background per-user PSS measurement, in seconds.",
		nil, nil,
	)
	snapshotAgeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "snapshot_age_seconds"),
		"Age of the latest completed background /proc walk shared by the user_* collectors, in seconds. Scrapes read this cached snapshot, so this bounds how stale the user_* metrics are.",
		nil, nil,
	)
	snapshotDurationDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "snapshot_duration_seconds"),
		"Duration of the latest completed background /proc walk, in seconds.",
		nil, nil,
	)
	snapshotProcsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "snapshot_processes"),
		"Number of processes the latest /proc walk read. A count that shrinks while uptime grows means walks are being cut short.",
		nil, nil,
	)
	snapshotWalksDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "snapshot_walks_total"),
		"Total number of /proc walks, including partial ones.",
		nil, nil,
	)
	snapshotPartialDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, usermemInfoSubsystem, "snapshot_partial_walks_total"),
		"Number of /proc walks that ran out of their time budget and returned partial data. A count that climbs during a memory incident is the budget doing its job; one that climbs on an idle host means the budget is too low.",
		nil, nil,
	)
	collector := &usermemCollector{
		userDesc:               userDesc,
		userPSSDesc:            userPSSDesc,
		userPSSUnavailableDesc: userPSSUnavailableDesc,
		userPSSCacheAgeDesc:    userPSSCacheAgeDesc,
		userPSSDurationDesc:    userPSSDurationDesc,
		snapshotAgeDesc:        snapshotAgeDesc,
		snapshotDurationDesc:   snapshotDurationDesc,
		snapshotProcsDesc:      snapshotProcsDesc,
		snapshotWalksDesc:      snapshotWalksDesc,
		snapshotPartialDesc:    snapshotPartialDesc,
		collectPSS:             collectPSS,
		logger:                 logger,
	}
	return collector
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
	}

	// Health of the shared snapshot. Emitted from here because this is the
	// one user_* collector whose dashboard is about the machine's memory, the
	// same resource whose pressure makes walks slow. latestUserProcSnapshot
	// is a cache read, so this costs the scrape nothing.
	c.emitSnapshotHealth(ch)

	if c.collectPSS {
		c.emitPSS(ch, stats)
	}
	return nil
}

// emitSnapshotHealth reports the state of the shared /proc snapshot every
// user_* collector reads.
func (c *usermemCollector) emitSnapshotHealth(ch chan<- prometheus.Metric) {
	snap := latestUserProcSnapshot()
	if snap == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(
		c.snapshotAgeDesc, prometheus.GaugeValue, time.Since(snap.taken).Seconds(),
	)
	ch <- prometheus.MustNewConstMetric(
		c.snapshotDurationDesc, prometheus.GaugeValue, snap.duration.Seconds(),
	)
	ch <- prometheus.MustNewConstMetric(
		c.snapshotProcsDesc, prometheus.GaugeValue, float64(snap.procs),
	)
	ch <- prometheus.MustNewConstMetric(
		c.snapshotWalksDesc, prometheus.CounterValue, float64(userProcWalksTotal.Load()),
	)
	ch <- prometheus.MustNewConstMetric(
		c.snapshotPartialDesc, prometheus.CounterValue, float64(userProcPartialTotal.Load()),
	)
}

// emitPSS emits per-user PSS keyed off the RSS user list rather than the PSS
// snapshot's own list.
//
// The RSS list is what every scrape has. Measuring PSS only for processes
// above pss-min-rss-kb can leave a user -- one whose processes are all small,
// or one the measurement's budget never reached -- absent from the PSS
// snapshot, and an absent series is a hole in a dashboard: exactly the
// broken-line symptom the background design exists to prevent. Such a user
// emits a zero PSS with zero unavailable processes instead: stable series,
// honest values.
//
// Users present in the PSS snapshot but no longer in the RSS one had their
// processes die between the two walks; resurrecting their series would flap
// labels in and out of existence, so they are dropped.
func (c *usermemCollector) emitPSS(ch chan<- prometheus.Metric, stats []userMemStats) {
	snapshot := getUserPSSSnapshot()
	if snapshot == nil {
		return
	}

	measured := make(map[string]userPSSStat, len(snapshot.users))
	for _, s := range snapshot.users {
		measured[s.username] = s
	}

	for _, s := range stats {
		if m, ok := measured[s.labels.username]; ok {
			ch <- prometheus.MustNewConstMetric(
				c.userPSSDesc, prometheus.GaugeValue,
				float64(m.pssKB)*1024, s.labels.username, s.labels.env,
			)
			ch <- prometheus.MustNewConstMetric(
				c.userPSSUnavailableDesc, prometheus.GaugeValue,
				float64(m.unavailableProcs), s.labels.username, s.labels.env,
			)
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			c.userPSSDesc, prometheus.GaugeValue, 0, s.labels.username, s.labels.env,
		)
		ch <- prometheus.MustNewConstMetric(
			c.userPSSUnavailableDesc, prometheus.GaugeValue, 0, s.labels.username, s.labels.env,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.userPSSCacheAgeDesc, prometheus.GaugeValue, time.Since(snapshot.taken).Seconds(),
	)
	ch <- prometheus.MustNewConstMetric(
		c.userPSSDurationDesc, prometheus.GaugeValue, snapshot.duration.Seconds(),
	)
}

// GetStats turns the per-user RSS totals of the shared snapshot into byte counts.
//
// RSS comes from /proc/<pid>/status. PSS is collected asynchronously by the
// background refresher so reading smaps does not block user collectors.
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
			size: float64(agg.rssKB) * 1024,
		})
	}

	return stats, nil
}

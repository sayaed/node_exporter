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

//go:build linux && !nouserio
// +build linux,!nouserio

package collector

import (
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	userIOInfoSubsystem = "user_io"
)

var userIOLabelNames = []string{"username", "env"}

func init() {
	registerCollector("userio", defaultEnabled, NewUserIOCollector)
}

// userIOStats is the disk I/O attributed to all processes of one user.
type userIOStats struct {
	username   string
	env        string
	readBytes  uint64
	writeBytes uint64
	readOps    uint64
	writeOps   uint64
}

type userIOCollector struct {
	readBytesDesc  *prometheus.Desc
	writeBytesDesc *prometheus.Desc
	readOpsDesc    *prometheus.Desc
	writeOpsDesc   *prometheus.Desc
	logger         *slog.Logger
}

// NewUserIOCollector returns a new Collector exposing per-user disk I/O.
func NewUserIOCollector(logger *slog.Logger) (Collector, error) {
	// node_exporter only constructs a collector that is enabled, so reaching
	// this point is exactly the condition under which /proc/<pid>/io is worth
	// reading. See userIOReadNeeded.
	userIOReadNeeded.Store(true)

	readBytesDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userIOInfoSubsystem, "read_bytes_total"),
		"Total bytes read from disk by user processes.",
		userIOLabelNames, nil,
	)
	writeBytesDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userIOInfoSubsystem, "write_bytes_total"),
		"Total bytes written to disk by user processes.",
		userIOLabelNames, nil,
	)
	readOpsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userIOInfoSubsystem, "reads_completed_total"),
		"Approximate read operations based on major page faults (actual disk I/O).",
		userIOLabelNames, nil,
	)
	writeOpsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userIOInfoSubsystem, "writes_completed_total"),
		"Approximate write operations estimated from write_bytes (assuming 4KB average block size).",
		userIOLabelNames, nil,
	)
	return &userIOCollector{
		readBytesDesc:  readBytesDesc,
		writeBytesDesc: writeBytesDesc,
		readOpsDesc:    readOpsDesc,
		writeOpsDesc:   writeOpsDesc,
		logger:         logger,
	}, nil
}

func (c *userIOCollector) Update(ch chan<- prometheus.Metric) error {
	stats, err := c.GetStats()
	if err != nil {
		return err
	}

	for _, s := range stats {
		ch <- prometheus.MustNewConstMetric(
			c.readBytesDesc, prometheus.GaugeValue,
			float64(s.readBytes), s.username, s.env,
		)
		ch <- prometheus.MustNewConstMetric(
			c.writeBytesDesc, prometheus.GaugeValue,
			float64(s.writeBytes), s.username, s.env,
		)
		ch <- prometheus.MustNewConstMetric(
			c.readOpsDesc, prometheus.GaugeValue,
			float64(s.readOps), s.username, s.env,
		)
		ch <- prometheus.MustNewConstMetric(
			c.writeOpsDesc, prometheus.GaugeValue,
			float64(s.writeOps), s.username, s.env,
		)
	}
	return nil
}

// GetStats turns the per-user totals of the shared snapshot into I/O counters.
//
// The snapshot has already read /proc/<pid>/io and /proc/<pid>/stat and summed
// them per user -- including the per-process 4 KiB write-op estimate, which
// cannot be reconstructed from the byte totals alone. Nothing here touches
// /proc itself, and the rows come out sorted by username.
func (c *userIOCollector) GetStats() ([]userIOStats, error) {
	snapshot, err := getUserProcSnapshot()
	if err != nil {
		return nil, fmt.Errorf("failed to get process snapshot: %w", err)
	}

	out := make([]userIOStats, 0, len(snapshot.users))
	for _, agg := range snapshot.users {
		if agg.username == "" {
			// A process whose owner could not be resolved. The other
			// collectors do report it, under the empty username; this one has
			// always skipped it, because its I/O cannot be attributed either
			// way. Reported once per user rather than once per process, which
			// is what the per-process loop this replaces did.
			c.logger.Warn("Skipping processes with empty username", "count", agg.procs)
			continue
		}

		out = append(out, userIOStats{
			username:   agg.username,
			env:        agg.env,
			readBytes:  agg.readBytes,
			writeBytes: agg.writeBytes,
			// Major page faults are the closest available proxy for reads that
			// actually had to go to disk.
			readOps: agg.majflt,
			// /proc/<pid>/io has no completed-write counter, so the estimate is
			// one of bytes with a 4 KiB average block size, made per process.
			writeOps: agg.writeOps,
		})
	}

	return out, nil
}

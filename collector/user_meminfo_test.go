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
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestUserMemPSSCollectionIsOptional(t *testing.T) {
	userProcSnapshotMu.Lock()
	oldSnapshot := userProcSnapshotData
	userProcSnapshotMu.Unlock()
	userPSSSnapshotMu.Lock()
	oldPSSSnapshot := userPSSSnapshotData
	userPSSSnapshotMu.Unlock()
	t.Cleanup(func() {
		userProcSnapshotMu.Lock()
		userProcSnapshotData = oldSnapshot
		userProcSnapshotMu.Unlock()
		userPSSSnapshotMu.Lock()
		userPSSSnapshotData = oldPSSSnapshot
		userPSSSnapshotMu.Unlock()
	})

	userProcSnapshotMu.Lock()
	userProcSnapshotData = &userProcSnapshot{
		taken: time.Now(),
		users: []userAgg{{
			username: "test",
			rssKB:    10,
		}},
	}
	userProcSnapshotMu.Unlock()
	userPSSSnapshotMu.Lock()
	userPSSSnapshotData = &userPSSSnapshot{
		taken: time.Now(),
		users: []userPSSStat{{
			username:         "test",
			pssKB:            5,
			unavailableProcs: 1,
		}},
	}
	userPSSSnapshotMu.Unlock()

	for _, test := range []struct {
		name        string
		collectPSS  bool
		wantMetrics int
	}{
		// 1 RSS metric plus the five snapshot-health metrics. PSS enabled
		// adds, per RSS user, one PSS and one unavailable-processes metric,
		// then the PSS cache age and measurement duration: 6 + 4 = 10.
		{name: "disabled", collectPSS: false, wantMetrics: 6},
		{name: "enabled", collectPSS: true, wantMetrics: 10},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector := newUserMemCollector(slog.Default(), test.collectPSS)
			metrics := make(chan prometheus.Metric, 16)
			if err := collector.Update(metrics); err != nil {
				t.Fatalf("Update: %v", err)
			}
			if got := len(metrics); got != test.wantMetrics {
				t.Errorf("emitted %d metrics, want %d", got, test.wantMetrics)
			}
		})
	}
}

func TestUserMemPSSIsAbsentBeforeFirstBackgroundRefresh(t *testing.T) {
	userProcSnapshotMu.Lock()
	oldSnapshot := userProcSnapshotData
	userProcSnapshotData = &userProcSnapshot{
		taken: time.Now(),
		users: []userAgg{{username: "test", rssKB: 10}},
	}
	userProcSnapshotMu.Unlock()
	userPSSSnapshotMu.Lock()
	oldPSSSnapshot := userPSSSnapshotData
	userPSSSnapshotData = nil
	userPSSSnapshotMu.Unlock()
	t.Cleanup(func() {
		userProcSnapshotMu.Lock()
		userProcSnapshotData = oldSnapshot
		userProcSnapshotMu.Unlock()
		userPSSSnapshotMu.Lock()
		userPSSSnapshotData = oldPSSSnapshot
		userPSSSnapshotMu.Unlock()
	})

	collector := newUserMemCollector(slog.Default(), true)
	// One RSS metric plus the five snapshot-health metrics; the PSS snapshot
	// is absent, so the PSS block emits nothing at all.
	metrics := make(chan prometheus.Metric, 16)
	if err := collector.Update(metrics); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := len(metrics); got != 6 {
		t.Errorf("emitted %d metrics before the first PSS refresh, want 6", got)
	}
}

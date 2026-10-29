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

package collector

import "time"

// This file is deliberately free of build tags, unlike the rest of the
// userdiskinfo collector: it is plain bookkeeping over a map and needs neither
// /proc nor du, so the staleness rule can be unit tested on any platform
// instead of only on Linux.

// userdiskDirStat is one home directory: its last known size, and when that
// size was actually measured.
//
// The timestamp is per directory, not per pass. A directory whose du fails
// keeps the timestamp of the pass that last succeeded, which is what lets the
// staleness check below tell a fresh figure from a carried-over one.
type userdiskDirStat struct {
	size  int64
	taken time.Time
}

// stale reports whether this figure has gone too long without a successful
// re-measurement.
func (d userdiskDirStat) stale(now time.Time, staleAfter time.Duration) bool {
	return now.Sub(d.taken) > staleAfter
}

// staleUserdiskPaths returns the directories whose last successful measurement
// is older than staleAfter.
//
// Such a directory is no longer reported at all. Carrying its previous figure
// forward instead would be indistinguishable from a fresh one on a dashboard,
// because the pass itself succeeded and cache_age_seconds is reset every time.
func staleUserdiskPaths(sizes map[string]userdiskDirStat, staleAfter time.Duration) []string {
	now := time.Now()

	var stale []string
	for path, stat := range sizes {
		if stat.stale(now, staleAfter) {
			stale = append(stale, path)
		}
	}
	return stale
}

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

import (
	"testing"
	"time"
)

func TestStaleUserdiskPaths(t *testing.T) {
	const staleAfter = 15 * time.Minute
	now := time.Now()

	tests := []struct {
		name  string
		sizes map[string]userdiskDirStat
		want  []string
	}{
		{
			name:  "empty cache",
			sizes: map[string]userdiskDirStat{},
			want:  nil,
		},
		{
			name: "everything measured this pass",
			sizes: map[string]userdiskDirStat{
				"/home/a": {size: 1, taken: now},
				"/home/b": {size: 2, taken: now.Add(-time.Minute)},
			},
			want: nil,
		},
		{
			name: "one directory whose du keeps failing",
			sizes: map[string]userdiskDirStat{
				"/home/a": {size: 1, taken: now},
				"/home/b": {size: 2, taken: now.Add(-staleAfter - time.Second)},
			},
			want: []string{"/home/b"},
		},
		{
			name: "just inside the window",
			sizes: map[string]userdiskDirStat{
				"/home/a": {size: 1, taken: now.Add(-staleAfter + time.Second)},
			},
			want: nil,
		},
		{
			name: "just outside the window",
			sizes: map[string]userdiskDirStat{
				"/home/a": {size: 1, taken: now.Add(-staleAfter - time.Second)},
			},
			want: []string{"/home/a"},
		},
		{
			name: "a deleted directory is not stale, it is zero",
			// Size zero is already skipped by Update(); staleness is a
			// separate reason to drop a series and must not double-report.
			sizes: map[string]userdiskDirStat{
				"/home/gone": {size: 0, taken: now},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := staleUserdiskPaths(tt.sizes, staleAfter)
			if len(got) != len(tt.want) {
				t.Fatalf("staleUserdiskPaths() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("staleUserdiskPaths() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestUserdiskDirStatStale(t *testing.T) {
	const staleAfter = 15 * time.Minute
	now := time.Now()

	fresh := userdiskDirStat{size: 1, taken: now.Add(-staleAfter + time.Second)}
	if fresh.stale(now, staleAfter) {
		t.Errorf("a figure one second inside the window must not be stale")
	}

	old := userdiskDirStat{size: 1, taken: now.Add(-staleAfter - time.Second)}
	if !old.stale(now, staleAfter) {
		t.Errorf("a figure one second past the window must be stale")
	}
}

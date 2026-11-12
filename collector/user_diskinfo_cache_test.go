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

//go:build linux
// +build linux

package collector

import (
	"testing"
	"time"
)

func TestUserdiskCacheWithStat(t *testing.T) {
	oldStat := userdiskDirStat{size: 10, taken: time.Unix(1, 0)}
	newStat := userdiskDirStat{size: 20, taken: time.Unix(2, 0)}
	cache := &userdiskCache{
		sizes:    map[string]userdiskDirStat{"/home/old": oldStat},
		taken:    time.Unix(3, 0),
		duration: time.Minute,
	}

	got := userdiskCacheWithStat(cache, "/home/new", newStat)

	if got.sizes["/home/old"] != oldStat {
		t.Errorf("old entry = %+v, want %+v", got.sizes["/home/old"], oldStat)
	}
	if got.sizes["/home/new"] != newStat {
		t.Errorf("new entry = %+v, want %+v", got.sizes["/home/new"], newStat)
	}
	if _, exists := cache.sizes["/home/new"]; exists {
		t.Error("updated cache mutated the published snapshot")
	}
	if !got.taken.Equal(cache.taken) || got.duration != cache.duration {
		t.Errorf("cache metadata = (%v, %v), want (%v, %v)", got.taken, got.duration, cache.taken, cache.duration)
	}
}

func TestUserdiskCacheWithStatInitializesCache(t *testing.T) {
	stat := userdiskDirStat{size: 20, taken: time.Unix(2, 0)}

	got := userdiskCacheWithStat(nil, "/home/new", stat)

	if got.sizes["/home/new"] != stat {
		t.Errorf("new entry = %+v, want %+v", got.sizes["/home/new"], stat)
	}
	if !got.taken.Equal(stat.taken) {
		t.Errorf("cache taken = %v, want %v", got.taken, stat.taken)
	}
}

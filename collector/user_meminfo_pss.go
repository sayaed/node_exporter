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
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	userPSSRefreshInterval = time.Minute
	maxUserPSSWorkers      = 4
)

type userPSSStat struct {
	username         string
	env              string
	pssKB            uint64
	unavailableProcs int
}

type userPSSSnapshot struct {
	taken time.Time
	users []userPSSStat
}

var (
	userPSSSnapshotMu   sync.RWMutex
	userPSSSnapshotData *userPSSSnapshot
	userPSSOnce         sync.Once
)

func startUserPSSRefresher(logger *slog.Logger) {
	userPSSOnce.Do(func() {
		go func() {
			for {
				started := time.Now()
				snapshot, err := measureUserPSS()
				if err != nil {
					logger.Error("Background per-user PSS measurement failed, keeping previous values", "error", err)
				} else {
					userPSSSnapshotMu.Lock()
					userPSSSnapshotData = snapshot
					userPSSSnapshotMu.Unlock()

					logger.Debug("Background per-user PSS measurement completed",
						"users", len(snapshot.users), "duration", time.Since(started))
				}
				time.Sleep(userPSSRefreshInterval)
			}
		}()
	})
}

func getUserPSSSnapshot() *userPSSSnapshot {
	userPSSSnapshotMu.RLock()
	defer userPSSSnapshotMu.RUnlock()
	return userPSSSnapshotData
}

func measureUserPSS() (*userPSSSnapshot, error) {
	pids, err := listProcPIDs()
	if err != nil {
		return nil, err
	}
	refreshUIDNameMap()

	users := make(map[string]userPSSStat, min(len(pids), userAggregateHint))
	var usersMu sync.Mutex
	var next atomic.Int64
	var wg sync.WaitGroup

	workers := min(max(runtime.NumCPU(), 1), maxUserPSSWorkers, len(pids))
	for range workers {
		wg.Go(func() {
			var reader procReader
			for {
				i := int(next.Add(1)) - 1
				if i >= len(pids) {
					return
				}

				username, pssKB, available, ok := reader.readUserPSS(pids[i])
				if !ok {
					continue
				}

				usersMu.Lock()
				user := users[username]
				user.username = username
				user.env = parseUserEnv(username)
				if available {
					user.pssKB += pssKB
				} else {
					user.unavailableProcs++
				}
				users[username] = user
				usersMu.Unlock()
			}
		})
	}
	wg.Wait()

	stats := make([]userPSSStat, 0, len(users))
	for _, user := range users {
		stats = append(stats, user)
	}
	slices.SortFunc(stats, func(a, b userPSSStat) int {
		return strings.Compare(a.username, b.username)
	})

	return &userPSSSnapshot{taken: time.Now(), users: stats}, nil
}

func (r *procReader) readUserPSS(pid int) (string, uint64, bool, bool) {
	status, err := r.readInto(r.processFile(pid, "/status"))
	if err != nil {
		return "", 0, false, false
	}
	uid, _, ok := parseStatusUIDAndRSS(status)
	if !ok {
		return "", 0, false, false
	}

	username := lookupUsernameID(uid)
	pssKB, available := r.readPSS(pid)
	return username, pssKB, available, true
}

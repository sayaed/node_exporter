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

// Deliberately carries no build tag, like the file it tests.

package collector

import (
	"strconv"
	"strings"
	"testing"
)

// synthRows builds a deterministic set of rows for the roll-up: n processes
// spread over `users` accounts, some accounts whose name carries an environment
// suffix, one process that vanished mid-walk, and one whose owner could not be
// resolved.
func synthRows(n, users int) []userProcInfo {
	rows := make([]userProcInfo, 0, n+16)

	for i := range n {
		rows = append(rows, userProcInfo{
			PID:        1000 + i,
			UID:        uint32(i % users),
			User:       "acct" + strconv.Itoa(i%users),
			RSSKB:      uint64(1024 + i%8192),
			Threads:    1 + i%8,
			CPUTicks:   uint64(100000 + i*3),
			Majflt:     uint64(i % 97),
			ReadBytes:  uint64(1<<20 + i),
			WriteBytes: uint64(1<<20 + i*7),
		})
	}

	// Per-environment accounts, which is what parseUserEnv is for.
	for i := range 7 {
		rows = append(rows, userProcInfo{
			PID:        9000 + i,
			User:       "envuser_" + strconv.Itoa(10+i),
			RSSKB:      4096,
			Threads:    2,
			CPUTicks:   77,
			Majflt:     3,
			ReadBytes:  2048,
			WriteBytes: 8192,
		})
	}

	// Zeroed: a process that disappeared mid-walk.
	rows = append(rows, userProcInfo{})

	// A process whose owner could not be resolved.
	rows = append(rows, userProcInfo{
		PID:        999999,
		User:       "",
		RSSKB:      512,
		Threads:    1,
		CPUTicks:   5,
		Majflt:     1,
		ReadBytes:  4096,
		WriteBytes: 4096,
	})

	return rows
}

// ---------------------------------------------------------------------------
// The four folds below are written the way the collectors did them before the
// roll-up moved into the snapshot: one map per collector, keyed by username,
// with the I/O one skipping rows whose owner is unknown. They are kept as the
// definition of what the single pass has to reproduce.
// ---------------------------------------------------------------------------

func foldCPU(rows []userProcInfo) map[string]uint64 {
	out := make(map[string]uint64, len(rows))
	for _, r := range rows {
		if r.PID == 0 {
			continue
		}
		out[r.User] += r.CPUTicks
	}
	return out
}

func foldMem(rows []userProcInfo) map[string]uint64 {
	out := make(map[string]uint64, len(rows))
	for _, r := range rows {
		if r.PID == 0 {
			continue
		}
		out[r.User] += r.RSSKB
	}
	return out
}

func foldProc(rows []userProcInfo) map[string][2]int {
	out := make(map[string][2]int, len(rows))
	for _, r := range rows {
		if r.PID == 0 {
			continue
		}
		counted := out[r.User]
		counted[0]++
		if r.Threads > 0 {
			counted[1] += r.Threads
		} else {
			// num_threads was unreadable; a live process still has one, and
			// the count has to stay below the thread total.
			counted[1]++
		}
		out[r.User] = counted
	}
	return out
}

func foldIO(rows []userProcInfo) map[string][4]uint64 {
	out := make(map[string][4]uint64, len(rows))
	for _, r := range rows {
		if r.PID == 0 || r.User == "" {
			continue
		}
		counted := out[r.User]
		counted[0] += r.ReadBytes
		counted[1] += r.WriteBytes
		counted[2] += r.Majflt
		counted[3] += r.WriteBytes >> 12
		out[r.User] = counted
	}
	return out
}

// ---------------------------------------------------------------------------

func TestAggregateUserStatsMatchesTheFourCollectorFolds(t *testing.T) {
	for _, tt := range []struct {
		name  string
		rows  int
		users int
	}{
		{"many processes, many accounts", 5000, 100},
		{"one process, one account", 1, 1},
		{"one process per account", 64, 64},
		{"only the edge-case rows", 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rows := synthRows(tt.rows, tt.users)
			got := aggregateUserStats(rows)

			wantCPU := foldCPU(rows)
			wantMem := foldMem(rows)
			wantProc := foldProc(rows)
			wantIO := foldIO(rows)

			// Every user the collectors used to report has to be present with
			// the same figures, and no extra user may appear.
			if len(got) != len(wantMem) {
				t.Fatalf("roll-up has %d users, the folds have %d", len(got), len(wantMem))
			}

			seen := make(map[string]bool, len(got))
			for _, agg := range got {
				if seen[agg.username] {
					t.Fatalf("user %q appears twice in the roll-up", agg.username)
				}
				seen[agg.username] = true

				if agg.cpuTicks != wantCPU[agg.username] {
					t.Errorf("%s: cpuTicks %d, fold says %d", agg.username, agg.cpuTicks, wantCPU[agg.username])
				}
				if agg.rssKB != wantMem[agg.username] {
					t.Errorf("%s: rssKB %d, fold says %d", agg.username, agg.rssKB, wantMem[agg.username])
				}
				if agg.procs != wantProc[agg.username][0] || agg.threads != wantProc[agg.username][1] {
					t.Errorf("%s: procs/threads %d/%d, fold says %d/%d",
						agg.username, agg.procs, agg.threads,
						wantProc[agg.username][0], wantProc[agg.username][1])
				}

				// The io collector skips an unknown owner, so it reports
				// nothing for that user; for every other user the four sums
				// have to match.
				if agg.username == "" {
					if wantIO[agg.username][0] != 0 {
						t.Error("the io fold counted a row with no owner")
					}
					continue
				}
				io := wantIO[agg.username]
				if agg.readBytes != io[0] || agg.writeBytes != io[1] ||
					agg.majflt != io[2] || agg.writeOps != io[3] {
					t.Errorf("%s: io %d/%d/%d/%d, fold says %d/%d/%d/%d",
						agg.username, agg.readBytes, agg.writeBytes, agg.majflt, agg.writeOps,
						io[0], io[1], io[2], io[3])
				}
			}
		})
	}
}

func TestAggregateUserStatsSortsByUsername(t *testing.T) {
	got := aggregateUserStats(synthRows(500, 60))

	names := make([]string, len(got))
	for i := range got {
		names[i] = got[i].username
	}

	if !stringsAreSorted(names) {
		t.Fatalf("roll-up is not sorted by username: %q", names)
	}
}

func stringsAreSorted(names []string) bool {
	for i := 1; i < len(names); i++ {
		if strings.Compare(names[i-1], names[i]) > 0 {
			return false
		}
	}
	return true
}

func TestAggregateUserStatsSkipsRowsThatVanished(t *testing.T) {
	rows := []userProcInfo{
		{PID: 1, User: "a", CPUTicks: 10},
		{}, // vanished mid-walk
		{PID: 3, User: "a", CPUTicks: 32},
	}

	got := aggregateUserStats(rows)
	if len(got) != 1 {
		t.Fatalf("got %d users, want 1: %+v", len(got), got)
	}
	if got[0].procs != 2 {
		t.Errorf("procs = %d, want 2", got[0].procs)
	}
	if got[0].cpuTicks != 42 {
		t.Errorf("cpuTicks = %d, want 42", got[0].cpuTicks)
	}
}

// The io collector has always reported a row for every user it can name, even
// when the io counters of that user's processes were all unreadable -- the user
// then simply contributes zero. That means the roll-up must keep a user that has
// processes but no io, and must not invent one that has neither.
func TestAggregateUserStatsKeepsUsersWithoutIO(t *testing.T) {
	rows := []userProcInfo{
		{PID: 1, User: "silent", Threads: 4}, // stat and io both unreadable
		{PID: 2, User: "busy", ReadBytes: 8, WriteBytes: 4096, Majflt: 2},
	}

	got := aggregateUserStats(rows)
	if len(got) != 2 {
		t.Fatalf("got %d users, want 2: %+v", len(got), got)
	}
	if got[0].username != "busy" || got[1].username != "silent" {
		t.Fatalf("sorted order is wrong: %q, %q", got[0].username, got[1].username)
	}
	if got[1].procs != 1 || got[1].readBytes != 0 || got[1].writeOps != 0 {
		t.Errorf("a user with unreadable io should still be reported, with zeroes: %+v", got[1])
	}
}

// The write-op estimate is deliberately summed per process. Rounding the total
// instead would give a different number, so this pins the behaviour down.
func TestAggregateUserStatsRoundsWriteOpsPerProcess(t *testing.T) {
	rows := []userProcInfo{
		{PID: 1, User: "a", WriteBytes: 3000},
		{PID: 2, User: "a", WriteBytes: 3000},
	}

	got := aggregateUserStats(rows)
	if got[0].writeOps != 0 {
		t.Errorf("writeOps = %d, want 0: two 3000-byte writes are 0 blocks each", got[0].writeOps)
	}
	// The other rounding, on the total, is what must not happen.
	if total := got[0].writeBytes >> 12; total == got[0].writeOps {
		t.Error("the fixture no longer distinguishes per-process rounding from rounding the total")
	}
}

func TestAggregateUserStatsEmptyInput(t *testing.T) {
	got := aggregateUserStats(nil)
	if len(got) != 0 {
		t.Errorf("aggregateUserStats(nil) = %+v, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// parseUserEnv lives next to the roll-up now, so it is covered here.
// ---------------------------------------------------------------------------

func TestParseUserEnv(t *testing.T) {
	tests := []struct {
		username string
		want     string
	}{
		{"alice_01", "01"},
		{"alice_99", "99"},
		{"alice_00", "00"},
		{"alice", ""},
		{"", ""},
		{"_", ""},
		{"alice_", ""},
		{"alice_1", ""},     // one digit
		{"alice_123", ""},   // three digits
		{"alice_ab", ""},    // not digits
		{"alice_a1", ""},    // first is not a digit
		{"alice_1a", ""},    // second is not a digit
		{"alice_01_02", ""}, // a second underscore
		{"alice_bob_01", ""},
		{"a_b_01", ""},
		{"_01", "01"}, // no name before the underscore

		// strconv.Atoi -- which the original Split-based version went through --
		// accepts a leading sign, and a username may contain '-'.
		{"alice_+1", "+1"},
		{"alice_-1", "-1"},
		{"alice_+a", ""},
		{"acct-1_07", "07"},
	}

	for _, tt := range tests {
		if got := parseUserEnv(tt.username); got != tt.want {
			t.Errorf("parseUserEnv(%q) = %q, want %q", tt.username, got, tt.want)
		}
	}
}

// The roll-up is the largest single piece of per-scrape work on a host with many
// processes, so it must stay at a handful of allocations. A non-zero allocs/op
// that keeps climbing means something per-process started allocating again --
// a *userAgg, a userAgg copied through the map, or a string built per row.
func BenchmarkAggregateUserStats(b *testing.B) {
	rows := synthRows(5000, 100)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sinkUserAggs = aggregateUserStats(rows)
	}
}

var sinkUserAggs []userAgg

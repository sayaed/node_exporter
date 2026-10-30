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

//go:build linux
// +build linux

package collector

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// These tests run against the real /proc of the host, so unlike the pure parser
// tests next to them they only mean anything on Linux. They cover what the
// parsers on their own cannot: the walk, the per-process reads, the io gating,
// and the agreement between the index-based parsers and an independent
// strings-based parse of the very same files.

func TestBuildUserProcSnapshotAgainstRealProc(t *testing.T) {
	// The snapshot only reads /proc/<pid>/io when the userio collector has been
	// built, so turn that on for the duration of this test to cover that path
	// as well.
	restoreIO := userIOReadNeeded.Load()
	restorePSS := userMemoryPSSReadNeeded.Load()
	userIOReadNeeded.Store(true)
	userMemoryPSSReadNeeded.Store(true)
	t.Cleanup(func() { userIOReadNeeded.Store(restoreIO) })
	t.Cleanup(func() { userMemoryPSSReadNeeded.Store(restorePSS) })

	procs, err := readUserProcs()
	if err != nil {
		t.Fatalf("readUserProcs: %v", err)
	}

	readable := make([]userProcInfo, 0, len(procs))
	for _, proc := range procs {
		if proc.PID != 0 {
			readable = append(readable, proc)
		}
	}

	if len(readable) == 0 {
		t.Fatal("the walk produced no processes")
	}

	own := os.Getpid()
	var foundSelf bool
	var withRSS, withPSS, withThreads int

	for _, proc := range readable {
		if proc.PID <= 0 {
			t.Errorf("snapshot contains a non-positive pid %d", proc.PID)
		}
		if proc.User == "" {
			t.Errorf("pid %d was not resolved to a username", proc.PID)
		}

		if proc.RSSKB > 0 {
			withRSS++
		}
		if proc.PSSAvailable && proc.PSSKB > 0 {
			withPSS++
		}
		if proc.Threads > 0 {
			withThreads++
		}

		if proc.PID != own {
			continue
		}
		foundSelf = true

		if proc.RSSKB == 0 {
			t.Errorf("the test process (pid %d) reports 0 KiB of resident memory", own)
		}
		if proc.PSSAvailable && proc.PSSKB == 0 {
			t.Errorf("the test process (pid %d) reports 0 KiB of proportional memory", own)
		}
		if proc.Threads == 0 {
			t.Errorf("the test process (pid %d) reports 0 threads", own)
		}
		if proc.CPUTicks == 0 {
			t.Errorf("the test process (pid %d) reports 0 CPU ticks", own)
		}
	}

	if !foundSelf {
		t.Errorf("the test process itself (pid %d) is missing from the snapshot", own)
	}
	if withRSS == 0 {
		t.Error("no process in the snapshot reports any resident memory")
	}
	if withPSS == 0 {
		t.Error("no process in the snapshot reports readable proportional memory")
	}
	if withThreads == 0 {
		t.Error("no process in the snapshot reports any threads")
	}

	// The walk is what feeds the roll-up, so check that the roll-up accounts for
	// every row the walk produced -- on real /proc rather than on a fixture.
	assertAggregateCoversRows(t, readable, buildUserProcSnapshotForTest(t).users)
}

// buildUserProcSnapshotForTest runs the snapshot build the collectors use.
func buildUserProcSnapshotForTest(t *testing.T) *userProcSnapshot {
	t.Helper()

	snapshot, err := buildUserProcSnapshot()
	if err != nil {
		t.Fatalf("buildUserProcSnapshot: %v", err)
	}
	return snapshot
}

// assertAggregateCoversRows checks that the per-user roll-up is exactly the fold
// of the given rows: same users, and the same totals.
func assertAggregateCoversRows(t *testing.T, rows []userProcInfo, aggs []userAgg) {
	t.Helper()

	want := aggregateUserStats(rows)
	if len(aggs) != len(want) {
		t.Fatalf("snapshot has %d users, the fold of its own rows has %d", len(aggs), len(want))
	}

	var wantProcs, gotProcs int
	for i := range want {
		if aggs[i] != want[i] {
			t.Errorf("user %q: snapshot %+v, fold of the rows %+v", want[i].username, aggs[i], want[i])
		}
		wantProcs += want[i].procs
		gotProcs += aggs[i].procs
	}

	if gotProcs != len(rows) {
		t.Errorf("the roll-up accounts for %d of the %d readable processes", gotProcs, len(rows))
	}
}

func TestListProcPIDs(t *testing.T) {
	pids, err := listProcPIDs()
	if err != nil {
		t.Fatalf("listProcPIDs: %v", err)
	}
	if len(pids) == 0 {
		t.Fatal("listProcPIDs returned nothing")
	}

	var foundSelf bool
	for _, pid := range pids {
		if pid <= 0 {
			t.Fatalf("listProcPIDs returned a non-positive pid %d", pid)
		}
		if pid == os.Getpid() {
			foundSelf = true
		}
	}
	if !foundSelf {
		t.Errorf("listProcPIDs did not include the test process (pid %d)", os.Getpid())
	}
}

func TestGetUserProcSnapshotCachesWithinTTL(t *testing.T) {
	first, err := getUserProcSnapshot()
	if err != nil {
		t.Fatalf("getUserProcSnapshot: %v", err)
	}
	second, err := getUserProcSnapshot()
	if err != nil {
		t.Fatalf("getUserProcSnapshot: %v", err)
	}
	if first != second {
		t.Error("two calls within the TTL returned different snapshots")
	}
}

func TestUserIOReadNeededSkipsTheIOFile(t *testing.T) {
	restoreIO := userIOReadNeeded.Load()
	userIOReadNeeded.Store(false)
	t.Cleanup(func() { userIOReadNeeded.Store(restoreIO) })

	procs, err := readUserProcs()
	if err != nil {
		t.Fatalf("readUserProcs: %v", err)
	}

	for _, proc := range procs {
		if proc.ReadBytes != 0 || proc.WriteBytes != 0 {
			t.Fatalf("pid %d reports io counters even though userio is not built", proc.PID)
		}
	}
}

func TestUserPSSReadNeededSkipsSmaps(t *testing.T) {
	restore := userMemoryPSSReadNeeded.Load()
	userMemoryPSSReadNeeded.Store(false)
	t.Cleanup(func() { userMemoryPSSReadNeeded.Store(restore) })

	procs, err := readUserProcs()
	if err != nil {
		t.Fatalf("readUserProcs: %v", err)
	}

	for _, proc := range procs {
		if proc.PSSAvailable {
			t.Fatalf("pid %d reports PSS even though the usermeminfo collector is disabled", proc.PID)
		}
	}
}

// TestProcReaderBuildsPathsInOneBuffer checks that the path buffer is reused and
// that the paths it produces are the ones the plain concatenation would give.
func TestProcReaderBuildsPathsInOneBuffer(t *testing.T) {
	var reader procReader

	for _, pid := range []int{1, 7, 99, 1234, 999999} {
		for _, name := range []string{"/status", "/stat", "/io", "/smaps_rollup", "/smaps"} {
			got := reader.processFile(pid, name)
			want := "/proc/" + strconv.Itoa(pid) + name
			if got != want {
				t.Fatalf("processFile(%d, %q) = %q, want %q", pid, name, got, want)
			}
		}
	}

	// Paths are at most 7 + 7 + 7 bytes, so one buffer serves them all: a change
	// that reallocated per call would show up here as a different backing array.
	reader.processFile(1, "/status")
	before := &reader.path[0]
	for _, pid := range []int{1234567, 42, 8} {
		reader.processFile(pid, "/io")
		if &reader.path[0] != before {
			t.Fatal("processFile replaced its buffer between two calls")
		}
	}
}

func TestProcReaderReusesItsBuffer(t *testing.T) {
	var reader procReader

	first, err := reader.readInto("/proc/self/status")
	if err != nil {
		t.Fatalf("readInto /proc/self/status: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("readInto returned no data for /proc/self/status")
	}

	// Both files fit minProcReadBuf, so the second read must land in the same
	// backing array rather than allocating another one.
	before := &reader.body[0]
	if _, err := reader.readInto("/proc/self/stat"); err != nil {
		t.Fatalf("readInto /proc/self/stat: %v", err)
	}
	if &reader.body[0] != before {
		t.Error("procReader replaced its buffer between two reads that both fit")
	}
}

// TestParsersMatchStringsParsingAgainstRealProc is the strongest check available
// without a second implementation of the file formats: for every readable
// process, the index-based parsers must produce exactly what a straightforward
// strings-based parse of the same bytes produces.
func TestParsersMatchStringsParsingAgainstRealProc(t *testing.T) {
	pids, err := listProcPIDs()
	if err != nil {
		t.Fatalf("listProcPIDs: %v", err)
	}

	var checked int

	for _, pid := range pids {
		base := "/proc/" + strconv.Itoa(pid)

		if status, err := os.ReadFile(base + "/status"); err == nil {
			uid, rss, ok := parseStatusUIDAndRSS(status)

			wantUID, wantRSS, wantOK := referenceStatus(status)
			if ok != wantOK || (ok && (uid != wantUID || rss != wantRSS)) {
				t.Errorf("pid %d status: got (%d, %d, %v), reference (%d, %d, %v)",
					pid, uid, rss, ok, wantUID, wantRSS, wantOK)
			}
			checked++
		}

		if stat, err := os.ReadFile(base + "/stat"); err == nil {
			if got, want, comparable := compareStatSample(stat); comparable {
				if got != want {
					t.Errorf("pid %d stat: got %+v, reference %+v", pid, got, want)
				}
			}
		}

		if ioData, err := os.ReadFile(base + "/io"); err == nil {
			gotRead, gotWrite := parseIOBytes(ioData)
			wantRead, wantWrite := referenceIO(ioData)
			if gotRead != wantRead || gotWrite != wantWrite {
				t.Errorf("pid %d io: got (%d, %d), reference (%d, %d)",
					pid, gotRead, gotWrite, wantRead, wantWrite)
			}
			checked++
		}
	}

	if checked == 0 {
		t.Skip("no /proc/<pid> file in this environment was readable")
	}
	t.Logf("compared %d files against the reference parse", checked)
}

// referenceStatus parses /proc/<pid>/status the obvious way, with strings.
func referenceStatus(status []byte) (uid uint32, rssKB uint64, ok bool) {
	for _, line := range strings.Split(string(status), "\n") {
		if value, found := strings.CutPrefix(line, "Uid:"); found {
			if fields := strings.Fields(value); len(fields) > 0 {
				if n, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
					uid, ok = uint32(n), true
				}
			}
		}
		if value, found := strings.CutPrefix(line, "VmRSS:"); found {
			if fields := strings.Fields(value); len(fields) > 0 {
				rssKB, _ = strconv.ParseUint(fields[0], 10, 64)
			}
		}
	}
	return uid, rssKB, ok
}

// compareStatSample parses /proc/<pid>/stat with strings.Fields and reports
// whether the result is comparable to what parseStatSample produced.
//
// statFields is not reused here on purpose: the point is an independent
// implementation, and strings.Fields over the last-')'-delimited remainder is
// the one the original collector used.
func compareStatSample(stat []byte) (got, want statSample, comparable bool) {
	closeParen := strings.LastIndex(string(stat), ")")
	if closeParen < 0 {
		return statSample{}, statSample{}, false
	}

	fields := strings.Fields(string(stat)[closeParen+1:])
	// majflt is field 12, utime 14, stime 15 and num_threads 20, i.e. indexes
	// 9, 11, 12 and 17 of the remainder.
	if len(fields) < 18 {
		return statSample{}, statSample{}, false
	}

	want.majflt, _ = strconv.ParseUint(fields[9], 10, 64)
	want.utime, _ = strconv.ParseUint(fields[11], 10, 64)
	want.stime, _ = strconv.ParseUint(fields[12], 10, 64)
	want.threads, _ = strconv.Atoi(fields[17])

	return parseStatSample(stat), want, true
}

// referenceIO parses /proc/<pid>/io with strings.
func referenceIO(ioData []byte) (readBytes, writeBytes uint64) {
	for _, line := range strings.Split(string(ioData), "\n") {
		if value, found := strings.CutPrefix(line, "read_bytes: "); found {
			readBytes, _ = strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		}
		if value, found := strings.CutPrefix(line, "write_bytes: "); found {
			writeBytes, _ = strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		}
	}
	return readBytes, writeBytes
}

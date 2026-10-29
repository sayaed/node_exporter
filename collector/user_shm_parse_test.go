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
	"strings"
	"testing"
)

// sysvipcShmSample is real /proc/sysvipc/shm content: the header the kernel
// prints, followed by three segments owned by two users. alice (uid 1001) holds
// one 4096 byte segment; bob (uid 1002) holds 1 MiB and 2 MiB.
const sysvipcShmSample = `       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap
         0     327680   600                  4096  1234  1234      1  1001  1001  1001  1001 1774600000          0 1774600000                  4096                     0
   917531    294913   666                 1048576  4321  4321      2  1002  1002  1002  1002 1774600000          0 1774600000               1048576                     0
   917532    294914   666                 2097152  4321  4321      2  1002  1002  1002  1002 1774600000          0 1774600000               2097152                     0
`

func testUIDResolver(t *testing.T) func(string) string {
	t.Helper()
	names := map[string]string{"1001": "alice", "1002": "bob"}
	return func(uid string) string {
		return names[uid]
	}
}

func TestParseSysvipcShmRows(t *testing.T) {
	usage, total, err := parseSysvipcShmRows(strings.NewReader(sysvipcShmSample), testUIDResolver(t))
	if err != nil {
		t.Fatalf("parseSysvipcShmRows() error = %v", err)
	}

	if got, want := usage["alice"], int64(4096); got != want {
		t.Errorf("alice bytes = %d, want %d", got, want)
	}
	if got, want := usage["bob"], int64(1048576+2097152); got != want {
		t.Errorf("bob bytes = %d, want %d", got, want)
	}
	if got, want := len(usage), 2; got != want {
		t.Errorf("distinct users = %d, want %d", got, want)
	}
	if got, want := total, int64(4096+1048576+2097152); got != want {
		t.Errorf("total bytes = %d, want %d", got, want)
	}
	// The header line must not be counted as a segment.
	if _, ok := usage["size"]; ok {
		t.Error("header line was parsed as a segment")
	}
}

func TestParseSysvipcShmRowsWithoutHeader(t *testing.T) {
	// A header-less file must still parse via the documented positions.
	const noHeader = "         0     327680   600                  4096  1234  1234      1  1001  1001  1001  1001 1774600000          0 1774600000                  4096                     0\n"

	usage, total, err := parseSysvipcShmRows(strings.NewReader(noHeader), testUIDResolver(t))
	if err != nil {
		t.Fatalf("parseSysvipcShmRows() error = %v", err)
	}
	if got, want := usage["alice"], int64(4096); got != want {
		t.Errorf("alice bytes = %d, want %d", got, want)
	}
	if got, want := total, int64(4096); got != want {
		t.Errorf("total bytes = %d, want %d", got, want)
	}
}

func TestParseSysvipcShmRowsFollowsHeaderOrder(t *testing.T) {
	// Deliberately not the kernel's column order: the point is that the parser
	// reads the header rather than trusting fixed positions, so a kernel that
	// appends or reorders a column cannot silently shift us onto the wrong one.
	const reordered = `key uid shmid size
0 1001 327680 4096
`

	usage, total, err := parseSysvipcShmRows(strings.NewReader(reordered), testUIDResolver(t))
	if err != nil {
		t.Fatalf("parseSysvipcShmRows() error = %v", err)
	}
	if got, want := usage["alice"], int64(4096); got != want {
		t.Errorf("alice bytes = %d, want %d", got, want)
	}
	if got, want := total, int64(4096); got != want {
		t.Errorf("total bytes = %d, want %d", got, want)
	}
}

func TestParseSysvipcShmRowsUnresolvableOwner(t *testing.T) {
	// An owner that /etc/passwd and NSS cannot resolve must not be reported
	// under a made-up label.
	const unknownOwner = `key shmid perms size cpid lpid nattch uid gid cuid cgid atime dtime ctime rss swap
0 327680 600 4096 1234 1234 1 4242 4242 4242 4242 0 0 0 4096 0
`

	usage, total, err := parseSysvipcShmRows(strings.NewReader(unknownOwner), testUIDResolver(t))
	if err != nil {
		t.Fatalf("parseSysvipcShmRows() error = %v", err)
	}
	if len(usage) != 0 {
		t.Errorf("usage = %v, want empty", usage)
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
}

func TestParseSysvipcShmRowsSkipsMalformedRows(t *testing.T) {
	// A row whose uid column is not a number means the layout is not what we
	// expect; it must be dropped, not mislabelled.
	const shifted = `key shmid perms size cpid lpid nattch uid gid cuid cgid atime dtime ctime rss swap
0 327680 600 4096 1234 1234 1 not-a-uid 1002 1002 1002 0 0 0 4096 0
0 327680 600 4096 1234 1234 1 1002 1002 1002 1002 0 0 0 4096 0
`

	usage, total, err := parseSysvipcShmRows(strings.NewReader(shifted), testUIDResolver(t))
	if err != nil {
		t.Fatalf("parseSysvipcShmRows() error = %v", err)
	}
	if got, want := usage["bob"], int64(4096); got != want {
		t.Errorf("bob bytes = %d, want %d (only the well-formed row)", got, want)
	}
	if got, want := total, int64(4096); got != want {
		t.Errorf("total bytes = %d, want %d", got, want)
	}
}

func TestParseSysvipcShmRowsEmptyInput(t *testing.T) {
	for _, in := range []string{"", "\n", "       key      shmid perms                  size\n"} {
		usage, total, err := parseSysvipcShmRows(strings.NewReader(in), testUIDResolver(t))
		if err != nil {
			t.Fatalf("parseSysvipcShmRows(%q) error = %v", in, err)
		}
		if len(usage) != 0 || total != 0 {
			t.Errorf("parseSysvipcShmRows(%q) = %v, %d; want empty", in, usage, total)
		}
	}
}

func TestParseShmColumns(t *testing.T) {
	cols, ok := parseShmColumns(strings.Fields("key shmid perms size cpid lpid nattch uid gid cuid cgid atime dtime ctime rss swap"))
	if !ok {
		t.Fatal("parseShmColumns() did not find size and uid")
	}
	if cols.size != 3 || cols.uid != 7 {
		t.Errorf("parseShmColumns() = %+v, want {size:3 uid:7}", cols)
	}

	if _, ok := parseShmColumns(strings.Fields("key shmid perms")); ok {
		t.Error("parseShmColumns() reported success without size and uid columns")
	}
}

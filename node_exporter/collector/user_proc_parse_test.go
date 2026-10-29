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

// Deliberately carries no build tag, like the file it tests: these are pure
// text parsers, so the tests run on any platform instead of only on Linux.

package collector

import "testing"

// /proc/<pid>/stat layout, with the fields these tests care about:
//
//	pid (comm) state ppid pgrp session tty_nr tpgid flags \
//	    minflt cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads
//
// Field n of the file sits at index n-3 of the fields that statAfterComm
// returns, because pid, comm and the separating space are stripped.
const (
	// utime=5 stime=10 majflt=0 num_threads=1
	statNoSpaceInComm = "1234 (systemd) S 1 1234 1234 0 -1 4194560 1000 0 0 0 5 10 0 0 20 0 1 12345 123456 512 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"
	// utime=7 stime=20 majflt=3 num_threads=5 -- comm contains a space, which
	// shifts every field if the line is split on whitespace instead of on ')'
	statSpaceInComm = "4321 (Web Content) S 1 4321 4321 0 -1 4194560 2000 0 3 0 7 20 0 0 20 0 5 0 12345 123456 512 0 0 0 0"
	// utime=3 stime=4 majflt=1 num_threads=2 -- comm contains a closing paren
	statParenInComm = "777 (python3(1)) S 1 777 777 0 -1 4194560 500 0 1 0 3 4 0 0 20 0 2 0 12345 0 0"
	// num_threads is the very last token, exercising the end-of-line branch
	statTrailingThreads = "999 (x) S 1 2 3 4 -1 4194560 500 0 1 0 3 4 0 0 20 0 7"
)

func TestParseStatSample(t *testing.T) {
	tests := []struct {
		name        string
		stat        string
		wantUtime   uint64
		wantStime   uint64
		wantMajflt  uint64
		wantThreads int
	}{
		{"comm without space", statNoSpaceInComm, 5, 10, 0, 1},
		{"comm with space", statSpaceInComm, 7, 20, 3, 5},
		{"comm with paren", statParenInComm, 3, 4, 1, 2},
		{"num_threads at end of line", statTrailingThreads, 3, 4, 1, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseStatSample([]byte(tt.stat))

			if got.utime != tt.wantUtime {
				t.Errorf("utime: got %d, want %d", got.utime, tt.wantUtime)
			}
			if got.stime != tt.wantStime {
				t.Errorf("stime: got %d, want %d", got.stime, tt.wantStime)
			}
			if got.majflt != tt.wantMajflt {
				t.Errorf("majflt: got %d, want %d", got.majflt, tt.wantMajflt)
			}
			if got.threads != tt.wantThreads {
				t.Errorf("num_threads: got %d, want %d", got.threads, tt.wantThreads)
			}
		})
	}
}

func TestParseStatSampleRejectsUnparsableInput(t *testing.T) {
	for _, stat := range []string{"", "1 (foo) R 1 1", "1234 (systemd) S 1", "1234 (systemd"} {
		got := parseStatSample([]byte(stat))
		if got.threads != 0 || got.utime != 0 || got.stime != 0 {
			t.Errorf("parseStatSample(%q) = %+v, want the zero sample", stat, got)
		}
	}
}

func TestStatAfterComm(t *testing.T) {
	if got := statAfterComm(nil); got != nil {
		t.Errorf("statAfterComm(nil) = %v, want nil", got)
	}
	// No closing paren: nothing can be safely parsed.
	if got := statAfterComm([]byte("1234 (systemd")); got != nil {
		t.Errorf("statAfterComm(no closing paren) = %q, want nil", got)
	}
	// A closing paren as the last byte leaves no field to parse.
	if got := statAfterComm([]byte("1234 (systemd)")); got != nil {
		t.Errorf("statAfterComm(paren last) = %q, want nil", got)
	}
}

func TestParseStatusUIDAndRSS(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		wantUID  uint32
		wantRSS  uint64
		wantSeen bool
	}{
		{
			name:     "real uid is the first value",
			status:   "Name:\tsystemd\nUmask:\t0022\nTgid:\t1\nUid:\t1000\t0\t0\t0\nGid:\t1000\t0\t0\t0\nVmRSS:\t  1234 kB\n",
			wantUID:  1000,
			wantRSS:  1234,
			wantSeen: true,
		},
		{
			name:     "root",
			status:   "Name:\tinit\nUid:\t0\t0\t0\t0\nVmRSS:\t0 kB\n",
			wantUID:  0,
			wantRSS:  0,
			wantSeen: true,
		},
		{
			// Kernel threads have no VmRSS line at all.
			name:     "kernel thread has no VmRSS",
			status:   "Name:\tkworker/0:1\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
			wantUID:  0,
			wantRSS:  0,
			wantSeen: true,
		},
		{
			name:     "missing uid line",
			status:   "Name:\tinit\nGid:\t0\t0\t0\t0\n",
			wantSeen: false,
		},
		{
			name:     "empty input",
			status:   "",
			wantSeen: false,
		},
		{
			// A UID above 2^31 must not be truncated.
			name:     "high uid",
			status:   "Uid:\t4294967294\t4294967294\t4294967294\t4294967294\nVmRSS:\t7 kB\n",
			wantUID:  4294967294,
			wantRSS:  7,
			wantSeen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uid, rss, seen := parseStatusUIDAndRSS([]byte(tt.status))
			if seen != tt.wantSeen {
				t.Fatalf("seen: got %v, want %v", seen, tt.wantSeen)
			}
			if !seen {
				return
			}
			if uid != tt.wantUID {
				t.Errorf("uid: got %d, want %d", uid, tt.wantUID)
			}
			if rss != tt.wantRSS {
				t.Errorf("VmRSS: got %d, want %d", rss, tt.wantRSS)
			}
		})
	}
}

func TestParseIOBytes(t *testing.T) {
	tests := []struct {
		name      string
		io        string
		wantRead  uint64
		wantWrite uint64
	}{
		{
			// rchar and wchar must be ignored: they also count page-cache hits.
			name:      "full sample",
			io:        "rchar: 88123456\nwchar: 12345678\nsyscr: 123456\nsyscw: 7890\nread_bytes: 44040192\nwrite_bytes: 8388608\ncancelled_write_bytes: 0\n",
			wantRead:  44040192,
			wantWrite: 8388608,
		},
		{
			name:      "only read_bytes present",
			io:        "rchar: 1\nread_bytes: 4096\n",
			wantRead:  4096,
			wantWrite: 0,
		},
		{
			name:     "empty",
			io:       "",
			wantRead: 0, wantWrite: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read, write := parseIOBytes([]byte(tt.io))
			if read != tt.wantRead {
				t.Errorf("read_bytes: got %d, want %d", read, tt.wantRead)
			}
			if write != tt.wantWrite {
				t.Errorf("write_bytes: got %d, want %d", write, tt.wantWrite)
			}
		})
	}
}

func TestParseCPUSummaryTotal(t *testing.T) {
	// user=100 nice=20 system=30 idle=400 iowait=5 irq=0 softirq=6 steal=0,
	// then guest and guest_nice. Only the first eight fields are total CPU
	// time: the kernel documents guest as a subset of user and guest_nice as a
	// subset of nice, so they are there to be separated out, not added on.
	const want = 100 + 20 + 30 + 400 + 5 + 0 + 6 + 0

	total, ok := parseCPUSummaryTotal([]byte("cpu  100 20 30 400 5 0 6 0 0 0"))
	if !ok {
		t.Fatal("parseCPUSummaryTotal reported no number on a well-formed cpu line")
	}
	if total != want {
		t.Errorf("total: got %d, want %d", total, want)
	}

	// Non-zero guest counters must not change the result: counting them would
	// count time spent in a virtual CPU twice.
	total, ok = parseCPUSummaryTotal([]byte("cpu  100 20 30 400 5 0 6 0 11 13"))
	if !ok {
		t.Fatal("parseCPUSummaryTotal reported no number on a cpu line with guest counters")
	}
	if total != want {
		t.Errorf("total with guest counters: got %d, want %d", total, want)
	}

	// Kernels predating steal (2.6.24) and guest (2.6.33) print fewer fields,
	// and every field they do print counts.
	if total, ok := parseCPUSummaryTotal([]byte("cpu  1 2 3 4")); !ok || total != 1+2+3+4 {
		t.Errorf("short cpu line: got %d/%v, want %d/true", total, ok, 1+2+3+4)
	}

	// A cpu line with no counters at all is not the layout we expect.
	if _, ok := parseCPUSummaryTotal([]byte("cpu ")); ok {
		t.Error("parseCPUSummaryTotal reported a number on an empty cpu line")
	}
}

func TestParseUintField(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"0", 0, true},
		{"18446744073709551615", 18446744073709551615, true},
		{"", 0, false},
		{"12a", 0, false},
		{"-1", 0, false},
		{"123456789012345678901", 0, false}, // more digits than a uint64 can hold
	}

	for _, tt := range tests {
		got, ok := parseUintField([]byte(tt.in))
		if ok != tt.ok {
			t.Errorf("parseUintField(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("parseUintField(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestTokenAfterKey(t *testing.T) {
	tests := []struct {
		line string
		key  string
		want string
		ok   bool
	}{
		{"Uid:\t1000\t0\t0\t0", "Uid:", "1000", true},
		{"VmRSS:\t  1234 kB", "VmRSS:", "1234", true},
		{"read_bytes: 4096", "read_bytes:", "4096", true},
		{"Uid:", "Uid:", "", false},
		{"Uid:   ", "Uid:", "", false},
		{"Gid:\t0\t0\t0\t0", "Uid:", "", false},
	}

	for _, tt := range tests {
		got, ok := tokenAfterKey([]byte(tt.line), []byte(tt.key))
		if ok != tt.ok {
			t.Errorf("tokenAfterKey(%q, %q) ok = %v, want %v", tt.line, tt.key, ok, tt.ok)
			continue
		}
		if ok && string(got) != tt.want {
			t.Errorf("tokenAfterKey(%q, %q) = %q, want %q", tt.line, tt.key, got, tt.want)
		}
	}
}

func TestNextLine(t *testing.T) {
	body := []byte("a\nbb\n\nccc")

	var lines []string
	for off := 0; off < len(body); {
		line, next := nextLine(body, off)
		lines = append(lines, string(line))
		off = next
	}

	want := []string{"a", "bb", "", "ccc"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines %q, want %d", len(lines), lines, len(want))
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, lines[i], want[i])
		}
	}
}

// The parsers run once per process per scrape, so they must not allocate. These
// benchmarks are the regression guard for that: a non-zero allocs/op means a
// string conversion or a split crept back in.

func BenchmarkParseStatSample(b *testing.B) {
	stat := []byte(statSpaceInComm)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkStatSample = parseStatSample(stat)
	}
}

func BenchmarkParseStatusUIDAndRSS(b *testing.B) {
	status := []byte(statusSample)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkUint32, sinkUint64, _ = parseStatusUIDAndRSS(status)
	}
}

func BenchmarkParseIOBytes(b *testing.B) {
	ioData := []byte("rchar: 88123456\nwchar: 12345678\nsyscr: 123456\nsyscw: 7890\nread_bytes: 44040192\nwrite_bytes: 8388608\ncancelled_write_bytes: 0\n")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkUint64, sinkUint64B = parseIOBytes(ioData)
	}
}

var (
	sinkStatSample          statSample
	sinkUint32              uint32
	sinkUint64, sinkUint64B uint64
)

// statusSample is a realistic /proc/<pid>/status, about 1.5 KiB.
const statusSample = `Name:	Web Content
Umask:	0022
State:	S (sleeping)
Tgid:	12345
Ngid:	0
Pid:	12345
PPid:	1
TracerPid:	0
Uid:	1001	1001	1001	1001
Gid:	1001	1001	1001	1001
FDSize:	256
Groups:	1001 27 100
NStgid:	12345
NSpid:	12345
NSpgid:	12345
NSsid:	12345
VmPeak:	 4200000 kB
VmSize:	 3800000 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	  520000 kB
VmRSS:	  480000 kB
RssAnon:	  390000 kB
RssFile:	   80000 kB
RssShmem:	   10000 kB
VmData:	 1200000 kB
VmStk:	     132 kB
VmExe:	   20000 kB
VmLib:	   90000 kB
VmPTE:	    4000 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
CoreDumping:	0
THP_enabled:	1
Threads:	25
SigQ:	0/60000
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000000001000
SigCgt:	00000001800044e8
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	2
Speculation_Store_Bypass:	thread force mitigated
Cpus_allowed:	ff
Cpus_allowed_list:	0-7
Mems_allowed_list:	0-1
voluntary_ctxt_switches:	1024
nonvoluntary_ctxt_switches:	7
`

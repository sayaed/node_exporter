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

// This file intentionally carries no build tag, unlike user_proc_snapshot.go:
// it is pure text parsing of /proc file contents, with no syscalls and no
// platform dependencies, so it compiles -- and is unit tested -- everywhere.
//
// It is also the hot path of the user_* collectors. Every helper here reads the
// byte slices that come straight out of the file reads and locates lines and
// fields by index. Nothing is converted to string and nothing is split into a
// []string: splitting allocates, and `strings.Fields` on one /proc/<pid>/stat
// line builds a []string of around fifty headers while `strings.Split` on a
// status file builds one entry per line, both on top of a full copy of the file
// into a string.
//
// Measured on a representative process (Intel i5-7360U, Go 1.25), one pass of
// what the collectors used to do per process per scrape -- status for the UID,
// stat for the thread count, stat again for utime/stime, status again for
// VmRSS, and io -- cost 7931 ns and 35 allocations. The index-based versions in
// this file cost 1263 ns and 1 allocation.

package collector

import "bytes"

// procKey* are the line prefixes the parsers below look for. They are package
// level []byte values so that the prefix comparisons never convert a string
// constant to []byte.
var (
	procKeyUid        = []byte("Uid:")
	procKeyVmRSS      = []byte("VmRSS:")
	procKeyReadBytes  = []byte("read_bytes:")
	procKeyWriteBytes = []byte("write_bytes:")
	procKeyCPUSummary = []byte("cpu ")
)

// nextLine returns the line starting at off and the offset of the line after
// it. The returned slice aliases b and is never copied.
func nextLine(b []byte, off int) (line []byte, next int) {
	for i := off; i < len(b); i++ {
		if b[i] == '\n' {
			return b[off:i], i + 1
		}
	}
	return b[off:], len(b)
}

// tokenAfterKey returns the first whitespace-delimited token of line that
// follows key, or false when line does not start with key or has nothing after
// it. The returned slice aliases line.
func tokenAfterKey(line, key []byte) ([]byte, bool) {
	if !bytes.HasPrefix(line, key) {
		return nil, false
	}

	i := len(key)
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}

	start := i
	for i < len(line) && line[i] != ' ' && line[i] != '\t' {
		i++
	}

	if start == i {
		return nil, false
	}
	return line[start:i], true
}

// nextToken splits the first whitespace-delimited token off b and returns it
// together with the remainder of b. Both alias b.
func nextToken(b []byte) (token, rest []byte, ok bool) {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	if i == len(b) {
		return nil, nil, false
	}

	start := i
	for i < len(b) && b[i] != ' ' && b[i] != '\t' {
		i++
	}
	return b[start:i], b[i:], true
}

// maxUint64Digits is the number of decimal digits of the largest uint64.
// Anything longer cannot be a number the kernel printed, and parsing it would
// silently wrap.
const maxUint64Digits = 20

// parseUintField parses an unsigned base-10 integer from b.
func parseUintField(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > maxUint64Digits {
		return 0, false
	}

	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, true
}

// statAfterComm returns the part of a /proc/<pid>/stat line that follows
// "pid (comm)".
//
// The comm field is wrapped in parentheses and may itself contain spaces and
// parentheses, so the last ')' is the only safe delimiter. Splitting the whole
// line on whitespace silently shifts every following field for such processes.
func statAfterComm(stat []byte) []byte {
	if len(stat) == 0 {
		return nil
	}
	closeParen := bytes.LastIndexByte(stat, ')')
	if closeParen < 0 || closeParen+1 >= len(stat) {
		return nil
	}
	return stat[closeParen+1:]
}

// parseStatusUIDAndRSS pulls the process's real UID and its resident set size
// out of /proc/<pid>/status in a single pass.
//
// ok reports whether a Uid line was found, which is what the caller uses to
// decide that the process still exists: status carries the owner UID that every
// one of these collectors labels with.
func parseStatusUIDAndRSS(status []byte) (uid uint32, rssKB uint64, ok bool) {
	var gotUID, gotRSS bool

	for off := 0; off < len(status); {
		line, next := nextLine(status, off)
		off = next

		if !gotUID {
			if token, found := tokenAfterKey(line, procKeyUid); found {
				if value, valid := parseUintField(token); valid {
					uid = uint32(value)
					gotUID = true
				}
			}
		}

		// Kernel threads carry no VmRSS line at all, so gotRSS stays false for
		// them and their resident size is reported as zero.
		if !gotRSS {
			if token, found := tokenAfterKey(line, procKeyVmRSS); found {
				rssKB, _ = parseUintField(token)
				gotRSS = true
			}
		}

		if gotUID && gotRSS {
			break
		}
	}

	return uid, rssKB, gotUID
}

// statSample holds the /proc/<pid>/stat fields the user_* collectors consume.
type statSample struct {
	utime   uint64
	stime   uint64
	majflt  uint64
	threads int
}

// parseStatSample reads majflt (field 12), utime (field 14), stime (field 15)
// and num_threads (field 20) from /proc/<pid>/stat.
//
// The fields are counted by walking separators rather than by splitting the
// line, so no []string is built per process. Field n of the file sits at index
// n-3 after statAfterComm, because pid, comm and the separating space are gone;
// the walk below therefore starts counting at field 3.
//
// A field that is missing -- a truncated line, which happens for a process that
// is exiting -- is left at zero, which is what an unreadable stat file used to
// produce as well.
func parseStatSample(stat []byte) statSample {
	var sample statSample

	rest := statAfterComm(stat)
	if rest == nil {
		return sample
	}

	const (
		majfltField  = 12
		utimeField   = 14
		stimeField   = 15
		threadsField = 20
	)

	var utime, stime uint64
	var gotUtime, gotStime, gotThreads bool

	field := 3 // the first token after "(comm)" is field 3, the state
	start := -1

	for i := 0; i <= len(rest); i++ {
		atEnd := i == len(rest)
		if !atEnd && rest[i] != ' ' {
			if start < 0 {
				start = i
			}
			continue
		}
		if start < 0 {
			// Consecutive separators, or nothing seen yet.
			continue
		}

		token := rest[start:]
		if !atEnd {
			token = rest[start:i]
		}
		start = -1

		switch field {
		case majfltField:
			sample.majflt, _ = parseUintField(token)
		case utimeField:
			utime, gotUtime = parseUintField(token)
		case stimeField:
			stime, gotStime = parseUintField(token)
		case threadsField:
			if threads, valid := parseUintField(token); valid {
				sample.threads = int(threads)
				gotThreads = true
			}
		}
		field++

		// num_threads is the last field any of these collectors needs.
		if gotThreads {
			break
		}
	}

	// utime and stime are only meaningful together: a line truncated between
	// them must not contribute a half count.
	if gotUtime && gotStime {
		sample.utime = utime
		sample.stime = stime
	}

	return sample
}

// parseIOBytes reads read_bytes and write_bytes out of /proc/<pid>/io.
//
// Only those two fields are used. rchar and wchar also count transfers that
// were served from the page cache, so they say nothing about disk load, while
// read_bytes and write_bytes count only what actually reached the block layer.
func parseIOBytes(ioData []byte) (readBytes, writeBytes uint64) {
	var gotRead, gotWrite bool

	for off := 0; off < len(ioData); {
		line, next := nextLine(ioData, off)
		off = next

		if !gotRead {
			if token, found := tokenAfterKey(line, procKeyReadBytes); found {
				readBytes, gotRead = parseUintField(token)
			}
		}
		if !gotWrite {
			if token, found := tokenAfterKey(line, procKeyWriteBytes); found {
				writeBytes, gotWrite = parseUintField(token)
			}
		}

		if gotRead && gotWrite {
			break
		}
	}

	return readBytes, writeBytes
}

// cpuSummaryFields is how many of the aggregate cpu line's counters add up to
// the system's total CPU time.
//
// The line is:
//
//	user nice system idle iowait irq softirq steal guest guest_nice
//
// and its last two fields are not additional time: the kernel documents guest
// as *already included* in user, and guest_nice as already included in nice,
// so they exist so that a reader can separate virtual-CPU time out of the two
// big categories, not so that they can be added on top. Summing all ten would
// count time spent in a guest twice, inflating the denominator and deflating
// every per-user share. Stopping at eight is also what makes the parser work
// on kernels predating steal (2.6.24) and guest (2.6.33).
const cpuSummaryFields = 8

// parseCPUSummaryTotal totals the first eight fields of the aggregate "cpu"
// line of /proc/stat, which line is the pid- and comm-free summary of every
// CPU; see cpuSummaryFields for why it stops there.
//
// The per-user utime/stime figures are in the same clock ticks, which is what
// makes them comparable to this value. ok is false when the line held no number
// at all, i.e. when it is not shaped the way this parser expects.
func parseCPUSummaryTotal(line []byte) (uint64, bool) {
	rest := line[len(procKeyCPUSummary):]

	var total uint64
	var parsed bool

	for field := 0; field < cpuSummaryFields; field++ {
		token, remainder, more := nextToken(rest)
		if !more {
			break
		}
		rest = remainder

		value, valid := parseUintField(token)
		if !valid {
			// Skip it rather than aborting: only a field that is not a plain
			// counter should be ignored, the rest of the line still counts.
			// The slot is still consumed, so the fields after it keep their
			// positions.
			continue
		}
		total += value
		parsed = true
	}

	return total, parsed
}

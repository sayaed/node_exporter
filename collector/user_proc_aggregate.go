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

// This file deliberately carries no build tag, unlike user_proc_snapshot.go:
// it holds the row type the walk produces, the per-user roll-up of those rows,
// and the account name rule they share with the disk and shared memory
// collectors. None of it touches a syscall or a platform API, so keeping it out
// of the tagged file is what lets the roll-up -- the largest remaining piece of
// per-scrape work on a host with many processes -- be unit tested and
// benchmarked everywhere, the same way user_shm_parse.go and
// user_diskinfo_stale.go are.

package collector

import (
	"slices"
	"strings"
)

// userProcInfo is everything the user_* collectors need to know about a single
// process, already parsed.
//
// The raw /proc/<pid>/{stat,status,io,smaps} byte slices are deliberately not
// kept. Together they can be large per process; retaining only parsed numbers
// keeps the snapshot compact even when PSS is collected.
type userProcInfo struct {
	PID          int
	UID          uint32
	User         string
	RSSKB        uint64 // VmRSS from status, in kibibytes
	PSSKB        uint64 // Proportional set size, in kibibytes
	PSSAvailable bool   // Whether PSS was read and parsed successfully
	Threads      int    // num_threads, field 20 of stat
	CPUTicks     uint64 // utime + stime, fields 14 and 15 of stat
	Majflt       uint64 // major page faults, field 12 of stat
	ReadBytes    uint64 // read_bytes of io
	WriteBytes   uint64 // write_bytes of io
}

// userAgg is one user's totals, summed over every process it owns.
//
// It is built once, while the snapshot is built, rather than by each of the four
// collectors that need a per-user figure. Those used to walk the same rows four
// times, each with its own map, its own sort and its own call to parseUserEnv
// per user. Measured at 5000 processes over 100 accounts, that was 1001 us,
// 901 KiB and 272 allocations per scrape, against 179 us, 23 KiB and 5
// allocations for the single pass here.
//
// The fields are sums, not metric values: the collectors stay the only place
// that knows about label sets and units.
type userAgg struct {
	username string

	// env is derived from username alone and is stored rather than recomputed,
	// because all four collectors label with it and each one used to call
	// parseUserEnv once per user to get the same answer.
	env string

	procs               int
	threads             int
	rssKB               uint64
	pssKB               uint64
	pssUnavailableProcs int

	// cpuTicks is utime + stime, in clock ticks (USER_HZ), the same unit as the
	// system total in /proc/stat.
	cpuTicks uint64

	// majflt is the plain sum of the raw field; the io collector reads it as
	// its completed-read count, there being no such counter in /proc/<pid>/io
	// and a major fault being the closest available sign of a read that
	// actually reached the disk.
	majflt     uint64
	readBytes  uint64
	writeBytes uint64

	// writeOps is the one derived value that cannot be recovered from the sums
	// above: it is the sum of per-process (writeBytes >> 12), which is not the
	// same number as (sum of writeBytes) >> 12 -- rounding once instead of once
	// per process would shift the estimate -- so it has to be accumulated while
	// the per-process rows are still in hand.
	writeOps uint64
}

// userAggregateHint caps the initial capacity of the roll-up's lookup
// structures.
//
// The number of distinct owners of processes cannot exceed the number of
// processes, so the hint used is min(len(rows), this). Past the cap the map
// simply grows, which costs one rehash and nothing else; the cap only stops a
// host with thousands of processes from pre-allocating for an account count that
// is realistically in the tens or low hundreds. Measured on a 100-account host
// this size was both the fastest and the smallest of the candidates tried: a
// smaller hint makes the map rehash, a larger one only adds buckets.
const userAggregateHint = 128

// aggregateUserStats folds the per-process rows into one row per user, sorted by
// username.
//
// Rows for processes that disappeared mid-walk carry a zero PID and are skipped.
// listProcPIDs never yields pid 0 -- /proc/0 does not exist -- so a zero value
// cannot be mistaken for a real process.
//
// The sort is what makes the metric output stable between scrapes: without it
// the order would follow Go's map iteration and change on every gather.
func aggregateUserStats(procs []userProcInfo) []userAgg {
	hint := min(len(procs), userAggregateHint)

	// An index into the slice rather than a *userAgg or a userAgg: an int is
	// stored inline in the map bucket, so nothing is allocated per user, and
	// the row is only copied out once, at the end. A map[string]userAgg would
	// copy the whole struct on every update instead, which measured 341 us
	// against 179 us here; a map[string]*userAgg would allocate a 96-byte
	// object per user and land at 208 us.
	index := make(map[string]int, hint)
	out := make([]userAgg, 0, hint)

	for i := range procs {
		p := &procs[i]
		if p.PID == 0 {
			continue
		}

		at, ok := index[p.User]
		if !ok {
			out = append(out, userAgg{username: p.User, env: parseUserEnv(p.User)})
			at = len(out) - 1
			index[p.User] = at
		}

		// out may have been reallocated by the append above, so the row is
		// addressed again here rather than held across it.
		a := &out[at]
		a.procs++

		// A zero thread count means /proc/<pid>/stat could not be read. It does
		// not mean the process has no threads: num_threads is at least 1 for
		// every task the kernel has, so adding the zero through as before left
		// user_processes_threads_count strictly below user_processes_count for
		// such a user -- a combination that cannot occur, and that nothing
		// downstream can interpret. Counting it as the one thread it provably
		// has keeps the pair consistent; the alternative, dropping the process
		// from the count too, would contradict what the count is defined as.
		if p.Threads > 0 {
			a.threads += p.Threads
		} else {
			a.threads++
		}

		a.rssKB += p.RSSKB
		if p.PSSAvailable {
			a.pssKB += p.PSSKB
		} else {
			a.pssUnavailableProcs++
		}
		a.cpuTicks += p.CPUTicks
		a.majflt += p.Majflt
		a.readBytes += p.ReadBytes
		a.writeBytes += p.WriteBytes
		a.writeOps += p.WriteBytes >> 12
	}

	slices.SortFunc(out, func(a, b userAgg) int {
		return strings.Compare(a.username, b.username)
	})

	return out
}

// parseUserEnv extracts environment identifier from username
// Only extracts when username contains underscore followed by two digits
//
// The parts are located by index rather than built by strings.Split. This runs
// once per user per collector -- and once per core file -- so the []string that
// Split allocated on every call added up to several hundred allocations on a
// host with a hundred accounts, on every scrape.
//
// It is equivalent to the Split-based version it replaces, including the case
// that strconv.Atoi accepts a leading sign: a username is allowed to contain
// '-', so "_+1" and "_-1" still count as an environment identifier.
func parseUserEnv(username string) string {
	// 只有当下划线后跟两位数字时才提取环境变量
	//
	// Underscore present, exactly two characters after it (= Split yielding
	// two parts of the right length), and no second underscore.
	i := strings.IndexByte(username, '_')
	if i < 0 || i+3 != len(username) || strings.IndexByte(username[i+1:], '_') >= 0 {
		return ""
	}

	suffix := username[i+1:]
	first, second := suffix[0], suffix[1]

	// Both characters have to be digits, except that strconv.Atoi -- which the
	// Split-based version went through -- also accepts a leading sign.
	if !(second >= '0' && second <= '9') {
		return ""
	}
	if !((first >= '0' && first <= '9') || first == '+' || first == '-') {
		return ""
	}

	// A sub-slice of username, so nothing is allocated.
	return suffix
}

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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

var (
	// userProcRefreshInterval paces the background walk that keeps the shared
	// user_* snapshot warm. Scrapes themselves only read the cached snapshot
	// and never walk /proc, so the freshness of every user_* metric is bounded
	// by this value: set it to the scrape interval of the jobs that collect
	// the user_* metrics.
	userProcRefreshInterval = kingpin.Flag(
		"collector.userproc.refresh-interval",
		"How often the background walk of /proc rebuilds the shared user_* snapshot. Scrapes only read the cached snapshot.",
	).Default("30s").Duration()

	// userProcWalkBudget bounds one walk.
	//
	// Under a memory-reclaim or swap-in storm -- the minutes right after a
	// memory stress test ends -- every /proc/<pid>/status read contends for
	// the target's mmap_lock with the kernel's reclaim work and can slow down
	// by orders of magnitude. A walk that runs out of budget stops where it
	// is and returns the rows it has: the snapshot is partial, but the
	// scrape is not, and the next background walk gets a fresh budget.
	userProcWalkBudget = kingpin.Flag(
		"collector.userproc.walk-budget",
		"Max wall time for one /proc walk; an over-budget walk returns partial data rather than blocking scrapes.",
	).Default("4s").Duration()

	userProcRefreshOnce sync.Once
)

const (
	// maxUserProcSnapshotWorkers caps the fan-out of the walk. The actual
	// number of readers is min(NumCPU, this, number of processes), so a small
	// host uses proportionally fewer and a 128-core host does not start 128 of
	// them to read a few hundred files.
	maxUserProcSnapshotWorkers = 16

	// minProcReadBuf is the starting size of a worker's read buffer.
	// /proc/<pid>/status is the largest file read here and is normally around
	// 1.5 KiB, so one buffer of this size covers it without growing.
	minProcReadBuf = 4096
)

// userProcSnapshot is an immutable point-in-time view of /proc.
//
// It holds the per-user roll-up rather than the per-process rows the walk
// produced. Nothing consumes the rows: every user_* collector wants a per-user
// total, and the walk visits each process exactly once, so folding there is
// both cheaper than four separate folds in the collectors and enough to let the
// rows go. Keeping them would pin another 88 bytes per process -- 440 KiB at
// 5000 processes -- for the whole lifetime of the snapshot, for no reader.
type userProcSnapshot struct {
	taken    time.Time
	duration time.Duration
	partial  bool
	users    []userAgg

	// procs is the number of rows the walk actually read. It backs
	// node_user_use_memory_snapshot_processes, which turns "the snapshot is
	// getting thin" -- a budget that keeps running out on a busy host -- into
	// something a dashboard can show next to the age.
	procs int

	// rssByPID indexes each measured process's RSS for the PSS refresher,
	// which skips the smaps read of processes too small to be worth it.
	//
	// It is built only when PSS is enabled (userPSSNeedsRSSHint): nothing
	// else consumes it, and at 50k processes it would otherwise pin about
	// 2.5 MB per snapshot for no reader. A parallel pair of slices would be
	// tighter still, but the map keeps the refresher's lookup one line.
	rssByPID map[int]uint64
}

var (
	// userPSSNeedsRSSHint is set by NewUserMemCollector when the PSS
	// refresher is enabled. It lives here, rather than user_meminfo.go's
	// kingpin flag being read directly, because this file builds under plain
	// "linux" while that flag exists only without the nousermeminfo tag.
	userPSSNeedsRSSHint atomic.Bool

	userProcSnapshotMu   sync.RWMutex
	userProcSnapshotData *userProcSnapshot

	// userProcBuildMu serialises the cold start: the very first scrape after
	// process start may find no snapshot yet, and the collectors of that
	// scrape -- seven of them, running concurrently -- must not each build
	// their own. It is never held by the background refresher.
	userProcBuildMu sync.Mutex

	// userProcWalksTotal and userProcPartialTotal back the health metrics of
	// the same names: a partial count that climbs during incidents is the
	// budget doing its job, one that climbs while the host is idle means the
	// budget is set too low.
	userProcWalksTotal   atomic.Int64
	userProcPartialTotal atomic.Int64
)

// userIOReadNeeded is set by NewUserIOCollector, which node_exporter only calls
// for a collector that is actually enabled.
//
// Reading /proc/<pid>/io is the most expensive of the per-process files:
// it is gated on PTRACE_MODE_READ over the target, so an unprivileged exporter
// gets EACCES -- and, on a host that logs ptrace denials, an audit record -- for
// every process it does not own. When the only collector that consumes those
// counters is not built, reading the file is pure cost.
var userIOReadNeeded atomic.Bool

// getUserProcSnapshot returns the latest snapshot the background refresher
// produced.
//
// The read path is a lock-and-return: a scrape never walks /proc. That is the
// whole point of the design. The old behaviour rebuilt the snapshot on the
// scrape path whenever the cached copy was more than two seconds old, holding
// the mutex across the whole walk -- so one slow walk queued every collector of
// every scrape behind it, and after a memory stress test each queued scrape
// started yet another walk of its own. Prometheus cancels the HTTP request on
// timeout, but the Collect goroutines keep running, so the queue kept growing
// until the machine's reclaim storm subsided.
//
// Freshness is bounded by the refresh interval instead: data is at most one
// interval + one walk duration old, which is what the user_* metrics' scrape
// interval makes relevant anyway.
//
// The one synchronous path left is the cold start: before the background
// refresher has finished its first walk there is nothing to serve, so the first
// caller builds once here, under the walk budget. On a started exporter this
// never happens; in tests and on the very first requests it keeps the response
// complete instead of empty.
func getUserProcSnapshot() (*userProcSnapshot, error) {
	userProcSnapshotMu.RLock()
	s := userProcSnapshotData
	userProcSnapshotMu.RUnlock()
	if s != nil {
		return s, nil
	}

	userProcBuildMu.Lock()
	defer userProcBuildMu.Unlock()

	// The cold-start builder may have finished while this caller waited.
	userProcSnapshotMu.RLock()
	s = userProcSnapshotData
	userProcSnapshotMu.RUnlock()
	if s != nil {
		return s, nil
	}

	snapshot, err := buildUserProcSnapshot(*userProcWalkBudget)
	if err != nil {
		return nil, err
	}

	userProcSnapshotMu.Lock()
	userProcSnapshotData = snapshot
	userProcSnapshotMu.Unlock()
	return snapshot, nil
}

// latestUserProcSnapshot returns the cached snapshot without ever building one.
//
// The PSS refresher reads this to get its RSS hint, and it must not be able to
// trigger a walk: the background loops feed each other, never the other way
// around, or a slow walk would ask for another.
func latestUserProcSnapshot() *userProcSnapshot {
	userProcSnapshotMu.RLock()
	defer userProcSnapshotMu.RUnlock()
	return userProcSnapshotData
}

// startUserProcRefresher launches the background walk that keeps the shared
// snapshot warm. Every user_* collector constructor calls it, so enabling any
// one of them starts the walk; the constructor path is what tests bypass to
// stay deterministic.
func startUserProcRefresher() {
	userProcRefreshOnce.Do(func() {
		go func() {
			logger := slog.Default()
			for {
				snapshot, err := buildUserProcSnapshot(*userProcWalkBudget)
				if err != nil {
					logger.Error("Background /proc walk for the user_* snapshot failed, keeping previous values", "error", err)
				} else {
					userProcSnapshotMu.Lock()
					userProcSnapshotData = snapshot
					userProcSnapshotMu.Unlock()

					logger.Debug("Background /proc walk completed",
						"processes", snapshot.procs,
						"partial", snapshot.partial,
						"duration", snapshot.duration)
				}
				time.Sleep(*userProcRefreshInterval)
			}
		}()
	})
}

// buildUserProcSnapshot walks /proc once and folds what it finds into per-user
// totals. budget bounds the walk; a walk that exceeds it reports partial=true
// and carries only the rows that made it in time.
func buildUserProcSnapshot(budget time.Duration) (*userProcSnapshot, error) {
	started := time.Now()
	procs, partial, err := readUserProcs(started.Add(budget))
	if err != nil {
		return nil, err
	}

	if partial {
		userProcPartialTotal.Add(1)
	}
	userProcWalksTotal.Add(1)

	snapshot := &userProcSnapshot{
		taken:    time.Now(),
		duration: time.Since(started),
		partial:  partial,
		users:    aggregateUserStats(procs),
	}

	var readable int
	for i := range procs {
		if procs[i].PID == 0 {
			continue
		}
		readable++
		if userPSSNeedsRSSHint.Load() {
			if snapshot.rssByPID == nil {
				snapshot.rssByPID = make(map[int]uint64, readable)
			}
			snapshot.rssByPID[procs[i].PID] = procs[i].RSSKB
		}
	}
	snapshot.procs = readable

	return snapshot, nil
}

// readUserProcs reads and parses the per-process files shared by the user_*
// collectors and returns one row per process. PSS is read separately in the
// background; I/O reads are enabled only when userio is enabled.
//
// Reading the union in a single pass is deliberate: it avoids separate walks
// for each collector and guarantees that every collector sees the same values
// for the same process.
//
// The walk used to be the single largest piece of latency on the scrape path
// for hosts with many processes; it now runs in the background, and this
// function is called only from there and from the cold start in
// getUserProcSnapshot. The per-process reads still run on a small pool of
// workers instead of one after another, and the deadline stops the walk in
// place when the machine is too slow to finish it: partial data beats a
// timeout. Each worker writes to its own index, so the rows still come out in
// /proc order and the result is deterministic.
//
// A process that disappeared mid-walk, or whose status file could not be read,
// leaves its slot zeroed: the returned slice is the full length of the PID list,
// and a caller must skip entries whose PID is zero. A real process always has a
// PID above zero, because listProcPIDs never yields pid 0.
//
// The second return value reports whether the deadline cut the walk short.
func readUserProcs(deadline time.Time) ([]userProcInfo, bool, error) {
	pids, err := listProcPIDs()
	if err != nil {
		return nil, false, err
	}

	// Merge /etc/passwd before the workers start, so that the common case --
	// every UID on the machine is a local account -- is a map lookup inside the
	// workers and never reaches NSS. A UID that is missing from it still costs
	// one NSS round trip, which is why readProcess resolves the name while the
	// other workers are reading; see the comment there.
	refreshUIDNameMap()

	readIO := userIOReadNeeded.Load()
	procs := make([]userProcInfo, len(pids))

	var next atomic.Int64
	var wg sync.WaitGroup
	var partial atomic.Bool

	workers := min(max(runtime.NumCPU(), 1), maxUserProcSnapshotWorkers, len(pids))
	for range workers {
		wg.Go(func() {
			// One reader per worker, so its buffers are reused across every
			// process that worker handles.
			var reader procReader
			for {
				i := int(next.Add(1)) - 1
				if i >= len(pids) {
					return
				}
				// The deadline is checked per pid rather than per read: a
				// time.Now call costs nanoseconds, and a read that has
				// already started is cheap to let finish.
				if time.Now().After(deadline) {
					partial.Store(true)
					return
				}
				if info, ok := reader.readProcess(pids[i], readIO); ok {
					procs[i] = info
				}
			}
		})
	}
	wg.Wait()

	return procs, partial.Load(), nil
}

// listProcPIDs returns the numeric process IDs under /proc.
//
// The directory is read in batches and only the PIDs are kept, rather than
// using filepath.Glob -- which matches every name in /proc against a pattern --
// or os.ReadDir, which materialises every entry of a directory that also
// contains acpi, bus, driver and the rest.
func listProcPIDs() ([]int, error) {
	dir, err := os.Open("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc: %w", err)
	}
	defer dir.Close()

	var pids []int
	for {
		entries, err := dir.ReadDir(128)

		for _, entry := range entries {
			name := entry.Name()
			// Cheap first-byte test before paying for the full parse.
			if len(name) == 0 || name[0] < '0' || name[0] > '9' {
				continue
			}
			pid, err := strconv.Atoi(name)
			if err != nil {
				continue
			}
			pids = append(pids, pid)
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to list /proc: %w", err)
		}
	}

	return pids, nil
}

// procReader reads /proc files into buffers it reuses across calls.
//
// os.ReadFile is not usable on this path. procfs reports size 0 for every file,
// and os.ReadFile responds by growing its buffer in 512-byte steps, so a 1.5 KiB
// status file costs two or three allocations and as many copies -- times three
// files, times every process, on every rebuild. One reader per worker makes the
// steady state allocation free.
type procReader struct {
	body        []byte
	path        []byte
	smapsReader *bufio.Reader
}

// processFile returns the path of one file of a process.
//
// The path is assembled in a buffer that survives from call to call. Building it
// by concatenation instead -- base plus three suffixes -- costs four allocations
// per process: at 5000 processes that is 19901 allocations and 288 KiB of
// garbage per rebuild, against 15000 and 272 KiB here, because only the returned
// string still has to be allocated. That last allocation is not avoidable:
// os.Open takes a string.
//
// Named processFile rather than procFile so it is not confused with
// procFilePath, which resolves a path against the --path.procfs flag.
func (r *procReader) processFile(pid int, name string) string {
	r.path = r.path[:0]
	r.path = append(r.path, "/proc/"...)
	r.path = strconv.AppendInt(r.path, int64(pid), 10)
	r.path = append(r.path, name...)
	return string(r.path)
}

// readInto reads path and returns its contents.
//
// The returned slice is only valid until the next call on the same reader.
func (r *procReader) readInto(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if len(r.body) < minProcReadBuf {
		r.body = make([]byte, minProcReadBuf)
	}

	total := 0
	for {
		if total == len(r.body) {
			// The file turned out to be larger than the buffer: grow it, once
			// more than doubling so a big status file does not take many rounds.
			grown := make([]byte, len(r.body)*2)
			copy(grown, r.body[:total])
			r.body = grown
		}

		n, err := f.Read(r.body[total:])
		total += n
		if err != nil {
			if err == io.EOF {
				return r.body[:total], nil
			}
			return r.body[:total], err
		}
	}
}

// readPSS reads proportional set size. Older kernels without smaps_rollup use
// smaps, which is larger but exposes the same per-mapping Pss values.
func (r *procReader) readPSS(pid int) (uint64, bool) {
	f, err := os.Open(r.processFile(pid, "/smaps_rollup"))
	if errors.Is(err, os.ErrNotExist) {
		f, err = os.Open(r.processFile(pid, "/smaps"))
	}
	if err != nil {
		return 0, false
	}
	defer f.Close()

	if r.smapsReader == nil {
		r.smapsReader = bufio.NewReaderSize(f, minProcReadBuf)
	} else {
		r.smapsReader.Reset(f)
	}

	var pssKB uint64
	var foundPSS bool
	for {
		line, readErr := r.smapsReader.ReadSlice('\n')
		if readErr != bufio.ErrBufferFull {
			found, valid := addSmapsPSSLine(line, &pssKB)
			if !valid {
				return 0, false
			}
			foundPSS = foundPSS || found
		} else if bytes.HasPrefix(line, procKeyPSS) {
			return 0, false
		}

		switch readErr {
		case nil, bufio.ErrBufferFull:
			continue
		case io.EOF:
			return pssKB, foundPSS
		default:
			return 0, false
		}
	}
}

// readProcess reads and parses everything the user_* collectors need from one
// process.
//
// It reports false for a process that vanished mid-walk, and for one whose
// status file could not be read at all: status carries the owner UID that every
// collector labels with, so a process without it cannot be attributed to a user.
//
// The UID is resolved to a name here, inside the worker, rather than in a pass
// over the result afterwards. A UID that is not in /etc/passwd costs one NSS
// round trip, which on an SSSD- or LDAP-backed host can take seconds; doing it
// inside the pool lets that latency overlap with the other workers' file reads
// instead of stalling the tail of the rebuild -- which runs with the snapshot
// mutex held, so it would stall every user_* collector of the scrape.
func (r *procReader) readProcess(pid int, readIO bool) (userProcInfo, bool) {
	status, err := r.readInto(r.processFile(pid, "/status"))
	if err != nil {
		return userProcInfo{}, false
	}

	uid, rssKB, ok := parseStatusUIDAndRSS(status)
	if !ok {
		return userProcInfo{}, false
	}

	info := userProcInfo{PID: pid, UID: uid, User: lookupUsernameID(uid), RSSKB: rssKB}

	// stat and io are optional. stat is unreadable only for a process that is
	// exiting anyway, and io needs PTRACE_MODE_READ on the target.
	if stat, err := r.readInto(r.processFile(pid, "/stat")); err == nil {
		sample := parseStatSample(stat)
		info.Threads = sample.threads
		info.CPUTicks = sample.utime + sample.stime
		info.Majflt = sample.majflt
	}

	if readIO {
		if ioData, err := r.readInto(r.processFile(pid, "/io")); err == nil {
			info.ReadBytes, info.WriteBytes = parseIOBytes(ioData)
		}
	}

	return info, true
}

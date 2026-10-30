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
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// userProcSnapshotTTL bounds how long a single walk of /proc is reused.
	//
	// It has to be short enough that a normal scrape still sees fresh data, but
	// long enough to cover the spread between the user_* collectors of one
	// scrape. Those collectors run concurrently, so without this cache each of
	// them walks /proc and resolves every UID on its own.
	userProcSnapshotTTL = 2 * time.Second

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
// 5000 processes -- for the whole TTL, for no reader.
type userProcSnapshot struct {
	taken time.Time
	users []userAgg
}

var (
	userProcSnapshotMu   sync.Mutex
	userProcSnapshotData *userProcSnapshot
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
var userMemoryPSSReadNeeded atomic.Bool

// getUserProcSnapshot returns the cached snapshot, rebuilding it once the cached
// copy is older than userProcSnapshotTTL.
//
// The rebuild happens while holding the mutex on purpose: the collectors of one
// scrape call this concurrently, so the first caller walks /proc while the rest
// block briefly and then share the same result.
func getUserProcSnapshot() (*userProcSnapshot, error) {
	userProcSnapshotMu.Lock()
	defer userProcSnapshotMu.Unlock()

	if s := userProcSnapshotData; s != nil && time.Since(s.taken) < userProcSnapshotTTL {
		return s, nil
	}

	snapshot, err := buildUserProcSnapshot()
	if err != nil {
		// Degrade to the previous snapshot rather than failing the scrape.
		if userProcSnapshotData != nil {
			return userProcSnapshotData, nil
		}
		return nil, err
	}

	userProcSnapshotData = snapshot
	return snapshot, nil
}

// buildUserProcSnapshot walks /proc once and folds what it finds into per-user
// totals.
func buildUserProcSnapshot() (*userProcSnapshot, error) {
	procs, err := readUserProcs()
	if err != nil {
		return nil, err
	}

	return &userProcSnapshot{
		taken: time.Now(),
		users: aggregateUserStats(procs),
	}, nil
}

// readUserProcs reads and parses the per-process files the user_* collectors
// need between them, and returns one row per process. PSS and I/O reads are
// enabled only when their respective collectors are enabled.
//
// Reading the union in a single pass is deliberate: it avoids separate walks
// for each collector and guarantees that every collector sees the same values
// for the same process.
//
// The walk is the single largest piece of latency on the scrape path for hosts
// with many processes, so the per-process reads run on a small pool of workers
// instead of one after another. Each worker writes to its own index, so the
// rows still come out in /proc order and the result is deterministic.
//
// A process that disappeared mid-walk, or whose status file could not be read,
// leaves its slot zeroed: the returned slice is the full length of the PID list,
// and a caller must skip entries whose PID is zero. A real process always has a
// PID above zero, because listProcPIDs never yields pid 0.
func readUserProcs() ([]userProcInfo, error) {
	pids, err := listProcPIDs()
	if err != nil {
		return nil, err
	}

	// Merge /etc/passwd before the workers start, so that the common case --
	// every UID on the machine is a local account -- is a map lookup inside the
	// workers and never reaches NSS. A UID that is missing from it still costs
	// one NSS round trip, which is why readProcess resolves the name while the
	// other workers are reading; see the comment there.
	refreshUIDNameMap()

	readIO := userIOReadNeeded.Load()
	readPSS := userMemoryPSSReadNeeded.Load()

	procs := make([]userProcInfo, len(pids))

	var next atomic.Int64
	var wg sync.WaitGroup

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
				if info, ok := reader.readProcess(pids[i], readIO, readPSS); ok {
					procs[i] = info
				}
			}
		})
	}
	wg.Wait()

	return procs, nil
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
func (r *procReader) readProcess(pid int, readIO, readPSS bool) (userProcInfo, bool) {
	status, err := r.readInto(r.processFile(pid, "/status"))
	if err != nil {
		return userProcInfo{}, false
	}

	uid, rssKB, ok := parseStatusUIDAndRSS(status)
	if !ok {
		return userProcInfo{}, false
	}

	info := userProcInfo{PID: pid, UID: uid, User: lookupUsernameID(uid), RSSKB: rssKB}

	if readPSS {
		info.PSSKB, info.PSSAvailable = r.readPSS(pid)
	}

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

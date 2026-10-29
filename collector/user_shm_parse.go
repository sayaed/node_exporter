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

// This file intentionally carries no build tag, unlike user_shm.go: it is pure
// text parsing of /proc/sysvipc/shm with no syscalls and no platform
// dependencies, so it compiles -- and is unit tested -- everywhere.

package collector

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// shmColumns locates the two fields we read in /proc/sysvipc/shm.
//
// Rows are printed by sysvipc_shm_proc_show() in ipc/shm.c as
//
//	key shmid perms size cpid lpid nattch uid gid cuid cgid atime dtime ctime rss swap
//
// where size is shm_segsz in bytes and uid is the owning user as a number. The
// kernel also prints a header line naming every column, so the columns are
// resolved by name instead of being guessed from the field count the way the
// old `ipcs -m` parser had to (it picked between "owner" and "username"
// depending on how many fields a line happened to have).
type shmColumns struct {
	size int
	uid  int
}

// shmColumnsFallback is the documented layout above, used only when the header
// line is missing or does not name the columns we need.
var shmColumnsFallback = shmColumns{size: 3, uid: 7}

// parseShmColumns maps column names of a header line to their indexes.
func parseShmColumns(header []string) (shmColumns, bool) {
	cols := shmColumns{size: -1, uid: -1}
	for i, name := range header {
		switch name {
		case "size":
			cols.size = i
		case "uid":
			cols.uid = i
		}
	}
	return cols, cols.size >= 0 && cols.uid >= 0
}

// parseSysvipcShmRows totals SysV shared memory segments per owning user.
//
// It returns the bytes held per username plus the grand total, and takes the
// UID -> username resolver as an argument so it can be exercised without a
// real /etc/passwd. A segment whose owner cannot be resolved is skipped rather
// than attributed to a placeholder label.
func parseSysvipcShmRows(r io.Reader, usernameForUID func(string) string) (map[string]int64, int64, error) {
	usage := make(map[string]int64)
	var total int64

	cols := shmColumnsFallback
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		// Every data row starts with a numeric key; the only line that does
		// not is the kernel's header.
		if _, err := strconv.ParseInt(fields[0], 10, 64); err != nil {
			if parsed, ok := parseShmColumns(fields); ok {
				cols = parsed
			}
			continue
		}

		if cols.size >= len(fields) || cols.uid >= len(fields) {
			continue
		}

		size, err := strconv.ParseInt(fields[cols.size], 10, 64)
		if err != nil || size <= 0 {
			continue
		}

		// uid is numeric in /proc/sysvipc/shm. A non-numeric value means the
		// row is not shaped the way we expect, and guessing would mislabel the
		// segment, so drop it.
		if _, err := strconv.ParseUint(fields[cols.uid], 10, 32); err != nil {
			continue
		}

		username := usernameForUID(fields[cols.uid])
		if username == "" {
			continue
		}

		usage[username] += size
		total += size
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("error reading shared memory segments: %w", err)
	}

	return usage, total, nil
}

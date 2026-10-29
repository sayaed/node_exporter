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
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// User represents a system user account
type User struct {
	Username string
	UID      string
	GID      string
	HomeDir  string
	Shell    string
}

// passwdCache holds cached passwd file data
type passwdCache struct {
	users     []User
	timestamp time.Time
}

// Global cache for passwd file
var (
	passwdCacheData passwdCache
	passwdCacheMu   sync.RWMutex
	passwdCacheTTL  = 5 * time.Minute // Cache TTL
)

// uidNameMap maps a numeric UID to a username, so the hot path never goes
// through NSS per process. uidNameRefreshAt is the UnixNano timestamp of the
// last /etc/passwd merge; it is an atomic rather than a plain field so that the
// common "is the cache still fresh" test needs no lock at all.
var (
	uidNameMu        sync.RWMutex
	uidNameMap       = make(map[uint32]string)
	uidNameRefreshAt atomic.Int64
)

// lookupUsername resolves a numeric UID, given as a string, to a username.
//
// Anything that already has the UID as a number -- every per-process file read
// does -- must call lookupUsernameID instead, so that the hot path does not pay
// for a round trip through strconv.
func lookupUsername(uid string) string {
	numeric, err := strconv.ParseUint(uid, 10, 32)
	if err != nil {
		return uid
	}
	return lookupUsernameID(uint32(numeric))
}

// lookupUsernameID resolves a numeric UID to a username.
//
// /etc/passwd is merged in at most once per passwdCacheTTL, and a UID that is
// not in it (SSSD or LDAP backed accounts) costs exactly one user.LookupId call,
// memoised afterwards -- failures included, so an unresolvable UID is not
// retried for every process of every scrape. Anything that only needs a label
// must use this instead of calling user.LookupId directly.
func lookupUsernameID(uid uint32) string {
	uidNameMu.RLock()
	name, cached := uidNameMap[uid]
	uidNameMu.RUnlock()

	if cached {
		return name
	}

	if time.Since(time.Unix(0, uidNameRefreshAt.Load())) >= passwdCacheTTL {
		refreshUIDNameMap()

		uidNameMu.RLock()
		name, cached = uidNameMap[uid]
		uidNameMu.RUnlock()

		if cached {
			return name
		}
	}

	// Not a local account: fall back to a single NSS lookup and remember the
	// result, including a failure, under the numeric UID.
	name = strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}

	uidNameMu.Lock()
	uidNameMap[uid] = name
	uidNameMu.Unlock()

	return name
}

// refreshUIDNameMap merges /etc/passwd into uidNameMap, overwriting the UID
// entries it covers. Entries for UIDs that are not in the file -- LDAP or SSSD
// accounts -- are left alone, so a UID is still only ever looked up once.
func refreshUIDNameMap() {
	if time.Since(time.Unix(0, uidNameRefreshAt.Load())) < passwdCacheTTL {
		return
	}

	// Read the passwd file *before* taking the lock. This used to hold the
	// write lock across the open and the scan, which blocked every process's UID
	// lookup for the duration of a file read.
	users, err := parsePasswdFile()
	if err != nil {
		return
	}

	uidNameMu.Lock()
	defer uidNameMu.Unlock()

	if time.Since(time.Unix(0, uidNameRefreshAt.Load())) < passwdCacheTTL {
		// Another caller refreshed it while this one was reading.
		return
	}
	uidNameRefreshAt.Store(time.Now().UnixNano())

	// Every UID in /etc/passwd is written every refresh, overwriting whatever
	// was there. Only writing a UID the first time it is seen -- which is what
	// this did -- makes a wrong answer permanent: an NSS lookup that resolved
	// an LDAP account to a different name than the local file, or an account
	// that was renamed, would keep its stale label for the life of the
	// process, and user_diskinfo (which reads /etc/passwd through
	// parsePasswdFile and applies no such memory) would label the same user
	// differently. Two names for one user is two series with a single owner.
	//
	// A UID that is not in /etc/passwd at all is left untouched, so the
	// memoised NSS result -- success or failure -- still survives here.
	for _, u := range users {
		uid, err := strconv.ParseUint(u.UID, 10, 32)
		if err != nil {
			continue
		}
		uidNameMap[uint32(uid)] = u.Username
	}
}

// parsePasswdFile reads and parses the passwd file to extract user information
// with caching to improve performance
func parsePasswdFile() ([]User, error) {
	// Check cache first
	passwdCacheMu.RLock()
	if time.Since(passwdCacheData.timestamp) < passwdCacheTTL && passwdCacheData.users != nil {
		users := passwdCacheData.users
		passwdCacheMu.RUnlock()
		return users, nil
	}
	passwdCacheMu.RUnlock()

	// Read passwd file
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("failed to open passwd file: %w", err)
	}
	defer file.Close()

	var users []User
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) > 6 {
			users = append(users, User{
				Username: parts[0],
				UID:      parts[2],
				GID:      parts[3],
				HomeDir:  parts[5],
				Shell:    parts[6],
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning passwd file: %w", err)
	}

	// Update cache
	passwdCacheMu.Lock()
	passwdCacheData.users = users
	passwdCacheData.timestamp = time.Now()
	passwdCacheMu.Unlock()

	return users, nil
}

// invalidLoginShells are the shells that mean "this account cannot log in", as
// listed by /etc/shells and by the shadow-utils defaults. Package level so that
// isValidShell does not build a slice on every call -- parseUserDiskLabels
// calls it once per account per scrape.
var invalidLoginShells = []string{
	"/bin/false",
	"/bin/sync",
	"/usr/sbin/nologin",
	"/sbin/nologin",
	"/sbin/shutdown",
	"/sbin/halt",
}

// isValidShell checks if a shell is considered a valid login shell
func isValidShell(shell string) bool {
	return !slices.Contains(invalidLoginShells, shell)
}

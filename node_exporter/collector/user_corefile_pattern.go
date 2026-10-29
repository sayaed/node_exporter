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

// This file deliberately carries no build tag, unlike user_corefile.go: it is
// pure string handling over the value of /proc/sys/kernel/core_pattern, with no
// syscall and no platform dependency, so it compiles -- and is unit tested --
// everywhere. user_diskinfo_stale.go and user_shm_parse.go split their own pure
// logic out of the tagged files for the same reason.

package collector

import "strings"

// corePatternDirAndLeaf splits a core_pattern value into the directory the
// kernel writes core dumps into, and the glob pattern of the file names it
// writes there.
//
// /proc/sys/kernel/core_pattern holds one of three shapes:
//
//   - an absolute path with the kernel's own %X placeholders in it, such as
//     "/var/crash/core.%e.%p". This is the only shape that names a directory
//     which can be listed, and the only one that returns a non-empty dir.
//   - a bare name, "core", which each crashing process resolves against its
//     own working directory.
//   - a pipe, "|/usr/lib/systemd/systemd-coredump %P ...", which hands the
//     dump to a program instead of writing a file.
//
// The last two yield ("", ""), which is not an error: there is nothing to
// report, which is a different thing from something being wrong. A dir of "/"
// is returned as it stands, for a pattern such as "/core"; the caller decides
// what to do with it.
func corePatternDirAndLeaf(corePattern string) (dir, pattern string) {
	// If pattern doesn't start with '/', it's not a path
	if !strings.HasPrefix(corePattern, "/") {
		return "", "" // Core dumps go to current directory of the process
	}

	// 找到最后一个 '/' 并提取目录部分
	lastSlash := strings.LastIndex(corePattern, "/")
	// lastSlash is 0 only for "/core", where slicing would give "" -- an empty
	// dir is this function's way of saying "not a directory I can name", so
	// the root directory has to be spelled out.
	if lastSlash == 0 {
		return "/", coreLeafGlob(corePattern[1:])
	}
	return corePattern[:lastSlash], coreLeafGlob(corePattern[lastSlash+1:])
}

// coreLeafGlob turns the file name part of core_pattern into a glob pattern.
//
// The kernel expands each %X placeholder when it writes the dump, so those
// stand for an arbitrary run of characters in the real file name and have to be
// matched as one -- matching "%e" literally would match nothing the kernel ever
// produced, and would leave the metric missing for a directory that is in fact
// full of core dumps. Everything else in the leaf is literal, so the glob
// metacharacters are escaped rather than interpreted.
//
// An empty leaf -- a core_pattern ending in '/' -- gives an empty pattern. The
// kernel does write a file in that case, but which name it picks is not
// something this function can see, so the caller lists the whole directory
// rather than guess at a filter that would silently drop real core dumps.
func coreLeafGlob(leaf string) string {
	var b strings.Builder
	b.Grow(len(leaf))

	for i := 0; i < len(leaf); i++ {
		c := leaf[i]
		switch {
		case c == '%' && i+1 < len(leaf):
			b.WriteByte('*')
			i++ // the conversion character that follows '%'
		case c == '[' || c == '*' || c == '?' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

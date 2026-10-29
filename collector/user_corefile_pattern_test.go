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
	"path/filepath"
	"testing"
)

func TestCorePatternDirAndLeaf(t *testing.T) {
	tests := []struct {
		name        string
		corePattern string
		wantDir     string
		wantPattern string
	}{
		{
			name:        "apport style, with placeholders",
			corePattern: "/var/crash/core.%e.%p",
			wantDir:     "/var/crash",
			wantPattern: "core.*.*",
		},
		{
			name:        "no placeholders at all",
			corePattern: "/var/crash/core",
			wantDir:     "/var/crash",
			wantPattern: "core",
		},
		{
			name:        "nested directory",
			corePattern: "/var/lib/systemd/coredump/core.%u.%h.%t",
			wantDir:     "/var/lib/systemd/coredump",
			wantPattern: "core.*.*.*",
		},
		{
			name:        "directly in the root directory",
			corePattern: "/core",
			wantDir:     "/",
			wantPattern: "core",
		},
		{
			name:        "trailing slash names a directory, so there is no file name to match on",
			corePattern: "/var/crash/",
			wantDir:     "/var/crash",
			wantPattern: "",
		},
		{
			name:        "bare name is resolved against each process's working directory",
			corePattern: "core",
			wantDir:     "",
			wantPattern: "",
		},
		{
			name:        "systemd-coredump is a pipe, not a file",
			corePattern: "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %e",
			wantDir:     "",
			wantPattern: "",
		},
		{
			name:        "glob metacharacters in the leaf stay literal",
			corePattern: `/var/crash/co[re]*?.%p`,
			wantDir:     "/var/crash",
			// '[' is escaped because it opens a character class; the ']' after
			// it needs no escaping, being a literal wherever no class is open.
			wantPattern: `co\[re]\*\?.*`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, pattern := corePatternDirAndLeaf(tt.corePattern)
			if dir != tt.wantDir || pattern != tt.wantPattern {
				t.Errorf("corePatternDirAndLeaf(%q) = (%q, %q), want (%q, %q)",
					tt.corePattern, dir, pattern, tt.wantDir, tt.wantPattern)
			}
		})
	}
}

// The point of the leaf pattern is that it separates core dumps from whatever
// else happens to live in the directory they are written to. Listing a
// directory is not the same thing as finding core dumps in it, and reporting a
// README as somebody's core dump is a wrong series rather than a missing one.
func TestCoreLeafPatternSelectsCoreFiles(t *testing.T) {
	_, pattern := corePatternDirAndLeaf("/var/crash/core.%e.%p")
	if pattern == "" {
		t.Fatal("no pattern for an apport-style core_pattern")
	}

	// Names the kernel would produce under this pattern. %e is the crashing
	// binary's comm, which is free to contain spaces and punctuation.
	for _, name := range []string{"core.bash.12345", "core.Web Content.99", "core.python3!.7"} {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			t.Fatalf("filepath.Match(%q, %q): %v", pattern, name, err)
		}
		if !matched {
			t.Errorf("pattern %q does not match %q, which this core_pattern produces", pattern, name)
		}
	}

	// Names it would not produce. The pattern is a prefix filter, not a
	// validator: a file that happens to carry the same prefix still matches,
	// and that is as far as a name can be made to go.
	for _, name := range []string{"README", "core", "lastcore.bash.1"} {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			t.Fatalf("filepath.Match(%q, %q): %v", pattern, name, err)
		}
		if matched {
			t.Errorf("pattern %q matches %q, which this core_pattern does not produce", pattern, name)
		}
	}
}

// A leaf pattern that does not compile would make the collector report nothing
// at all, forever, and without saying so. Every core_pattern goes through
// coreLeafGlob, so every output of it has to be usable.
func TestCoreLeafGlobAlwaysCompiles(t *testing.T) {
	for _, leaf := range []string{
		"core", "core.%e.%p", "%e", "%", "%%", "a%b", "core.", ".core",
		`back\slash`, "brack[et", "star*", "quest?", "core.%e.%p.%h.%t",
	} {
		pattern := coreLeafGlob(leaf)
		if _, err := filepath.Match(pattern, "probe"); err != nil {
			t.Errorf("coreLeafGlob(%q) = %q, which does not compile: %v", leaf, pattern, err)
		}
	}
}

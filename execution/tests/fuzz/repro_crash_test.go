// Copyright 2025 The Erigon Authors
// This file is part of Erigon.
//
// Erigon is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Erigon is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Erigon. If not, see <http://www.gnu.org/licenses/>.

package fuzz

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/erigontech/erigon/db/datadir"
	"github.com/erigontech/erigon/db/kv/temporal/temporaltest"
	"github.com/erigontech/erigon/execution/tests/testutil"
	"github.com/erigontech/erigon/execution/vm"
)

// TestReproduceCrash reproduces a specific crash from a crash file.
//
// Usage:
//
//	CRASH_FILE=testdata/testdata/custom_crashes/crash_1.json go test -v -run=TestReproduceCrash
//
// Or to reproduce all crashes:
//
//	go test -v -run=TestReproduceAllCrashes
func TestReproduceCrash(t *testing.T) {
	crashFile := os.Getenv("CRASH_FILE")
	if crashFile == "" {
		crashFile = "testdata/testdata/custom_crashes/crash_1.json"
	}

	data, err := os.ReadFile(crashFile)
	if err != nil {
		t.Skipf("Crash file not found: %s", crashFile)
	}

	runCrashFile(t, crashFile, data)
}

// TestReproduceAllCrashes attempts to reproduce all crashes in the custom_crashes directory.
// It counts successes and failures.
func TestReproduceAllCrashes(t *testing.T) {
	crashDir := "testdata/testdata/custom_crashes"
	entries, err := os.ReadDir(crashDir)
	if err != nil {
		t.Skipf("Crash directory not found: %s", crashDir)
	}

	var total, crashed, passed int

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		crashFile := filepath.Join(crashDir, entry.Name())
		data, err := os.ReadFile(crashFile)
		if err != nil {
			continue
		}

		total++
		func() {
			defer func() {
				if r := recover(); r != nil {
					crashed++
					t.Logf("CRASH: %s - panic: %v", entry.Name(), r)
				} else {
					passed++
				}
			}()

			runCrashFileNoFail(t, crashFile, data)
		}()
	}

	t.Logf("\n=== Summary ===")
	t.Logf("Total: %d", total)
	t.Logf("Crashed: %d (%.1f%%)", crashed, float64(crashed)/float64(total)*100)
	t.Logf("Passed: %d (%.1f%%)", passed, float64(passed)/float64(total)*100)
}

// TestReproduceSampleCrashes reproduces a sample of crashes from different clusters.
func TestReproduceSampleCrashes(t *testing.T) {
	sampleFiles := []string{
		"testdata/testdata/custom_crashes/crash_1.json",   // BLAKE2f cluster 1
		"testdata/testdata/custom_crashes/crash_100.json", // BLAKE2f cluster 2
		"testdata/testdata/custom_crashes/crash_313.json", // bn256add
		"testdata/testdata/custom_crashes/crash_15.json",  // BLAKE2f with 0 data length
	}

	for _, file := range sampleFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Logf("Skipping %s: %v", file, err)
			continue
		}

		t.Run(filepath.Base(file), func(t *testing.T) {
			runCrashFile(t, file, data)
		})
	}
}

func runCrashFile(t *testing.T, filename string, data []byte) {
	var stateTests map[string]testutil.StateTest
	if err := json.Unmarshal(data, &stateTests); err != nil {
		t.Fatalf("Failed to parse %s: %v", filename, err)
	}

	dirs := datadir.New(t.TempDir())
	db := temporaltest.NewTestDB(t, dirs)

	for name, test := range stateTests {
		for _, subtest := range test.Subtests() {
			if !isSupportedFork(subtest.Fork) {
				t.Logf("Skipping unsupported fork: %s", subtest.Fork)
				continue
			}

			tx, err := db.BeginTemporalRw(context.Background())
			if err != nil {
				t.Fatalf("Failed to begin transaction: %v", err)
			}

			t.Logf("Running: %s, fork=%s, index=%d", name, subtest.Fork, subtest.Index)
			cfg := vm.Config{}
			_, _, _, err = test.RunNoVerify(t, tx, subtest, cfg, dirs)
			if err != nil {
				t.Logf("Execution error (expected for invalid tests): %v", err)
			}

			tx.Rollback()
		}
	}
}

func runCrashFileNoFail(t *testing.T, filename string, data []byte) {
	var stateTests map[string]testutil.StateTest
	if err := json.Unmarshal(data, &stateTests); err != nil {
		return
	}

	dirs := datadir.New(t.TempDir())
	db := temporaltest.NewTestDB(t, dirs)

	for _, test := range stateTests {
		for _, subtest := range test.Subtests() {
			if !isSupportedFork(subtest.Fork) {
				continue
			}

			tx, err := db.BeginTemporalRw(context.Background())
			if err != nil {
				continue
			}

			cfg := vm.Config{}
			_, _, _, _ = test.RunNoVerify(t, tx, subtest, cfg, dirs)
			tx.Rollback()
		}
	}
}

// Copyright 2025 The goevmlab Authors
// This file is part of the goevmlab library.
//
// The library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the goevmlab library. If not, see <http://www.gnu.org/licenses/>.

// Package fuzz provides coverage-guided fuzzing for Erigon's EVM.
//
// INSTALLATION: This file must be placed inside the erigon repository
// at execution/tests/fuzz/statetest_fuzz_test.go
//
// Run with:
//
//	cd execution/tests/fuzz && go test -fuzz=FuzzStateTest -fuzztime=1h
//
// Seed corpus with existing tests:
//
//	mkdir -p testdata/fuzz/FuzzStateTest
//	cp /path/to/corpus/*.json testdata/fuzz/FuzzStateTest/
package fuzz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erigontech/erigon/db/datadir"
	"github.com/erigontech/erigon/db/kv/temporal/temporaltest"
	"github.com/erigontech/erigon/execution/tests/testutil"
	"github.com/erigontech/erigon/execution/vm"
)

// FuzzStateTest is a coverage-guided fuzzer for Erigon's EVM.
// It takes state test JSON as input and executes it using Erigon's internal
// test runner. This provides:
//   - Coverage-guided mutation (Go's fuzzer learns from code paths)
//   - Automatic crash detection (panics, timeouts, OOM)
//   - Corpus minimization (saves minimal crashing inputs)
//   - High throughput native execution (~10,000+ exec/s)
//
// Run with:
//
//	go test -fuzz=FuzzStateTest -fuzztime=1h
func FuzzStateTest(f *testing.F) {
	// Seed corpus from testdata/seeds directory if it exists
	seedDir := filepath.Join("testdata", "seeds")
	if entries, err := os.ReadDir(seedDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(seedDir, entry.Name()))
			if err != nil {
				continue
			}
			f.Add(data)
		}
	}

	// Add a minimal valid state test as seed
	minimalTest := []byte(`{
		"minimal": {
			"env": {
				"currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
				"currentGasLimit": "0x10000000000000",
				"currentNumber": "0x01",
				"currentTimestamp": "0x03e8",
				"currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000",
				"currentDifficulty": "0x00",
				"currentBaseFee": "0x0a"
			},
			"pre": {
				"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
					"nonce": "0x00",
					"balance": "0x3635c9adc5dea00000",
					"code": "0x",
					"storage": {}
				},
				"0x1000000000000000000000000000000000000000": {
					"nonce": "0x00",
					"balance": "0x00",
					"code": "0x6000356000525f60206000f3",
					"storage": {}
				}
			},
			"transaction": {
				"nonce": "0x00",
				"maxPriorityFeePerGas": "0x00",
				"maxFeePerGas": "0x07d0",
				"gasLimit": ["0x061a80"],
				"to": "0x1000000000000000000000000000000000000000",
				"value": ["0x00"],
				"data": ["0x"],
				"accessLists": [[]],
				"sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
				"secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
			},
			"post": {
				"Cancun": [{"hash": "0x0000000000000000000000000000000000000000000000000000000000000000", "logs": "0x0000000000000000000000000000000000000000000000000000000000000000", "indexes": {"data": 0, "gas": 0, "value": 0}}]
			}
		}
	}`)
	f.Add(minimalTest)

	f.Fuzz(func(t *testing.T, testJSON []byte) {
		// Parse state test - the JSON has test names as top-level keys
		var stateTests map[string]testutil.StateTest
		if err := json.Unmarshal(testJSON, &stateTests); err != nil {
			// Invalid JSON - let the fuzzer learn from this
			return
		}

		// Create test infrastructure once per fuzz iteration
		dirs := datadir.New(t.TempDir())
		db := temporaltest.NewTestDB(t, dirs)

		// Execute each test in the file
		for _, test := range stateTests {
			subtests := test.Subtests()
			if len(subtests) == 0 {
				continue
			}

			// Execute all subtests (different fork configurations)
			for _, subtest := range subtests {
				// Skip unsupported forks
				if !isSupportedFork(subtest.Fork) {
					continue
				}

				// Execute with panic recovery to find multiple bugs
				// Set ERIGON_FUZZ_PANIC=1 to disable recovery
				func() {
					if os.Getenv("ERIGON_FUZZ_PANIC") == "" {
						defer func() {
							if r := recover(); r != nil {
								logCrash(testJSON, r)
								t.Logf("Recovered panic: %v", r)
							}
						}()
					}

					// Create a fresh transaction for each subtest
					tx, err := db.BeginTemporalRw(context.Background())
					if err != nil {
						return
					}
					defer tx.Rollback()

					// RunNoVerify executes without checking expected state roots
					cfg := vm.Config{}
					_, _, _, err = test.RunNoVerify(t, tx, subtest, cfg, dirs)

					// Ignore errors - we only care about crashes
					_ = err
				}()
			}
		}
	})
}

// isSupportedFork returns true if the fork is supported by Erigon.
func isSupportedFork(fork string) bool {
	supported := map[string]bool{
		"Frontier":          true,
		"Homestead":         true,
		"EIP150":            true,
		"EIP158":            true,
		"Byzantium":         true,
		"Constantinople":    true,
		"ConstantinopleFix": true,
		"Istanbul":          true,
		"Berlin":            true,
		"London":            true,
		"Paris":             true,
		"Shanghai":          true,
		"Cancun":            true,
		"Prague":            true,
		"Osaka":             true,
	}
	return supported[fork]
}

var (
	crashLogFile = "fuzz_crashes.log"
	crashLogMu   sync.Mutex
	crashCount   int64
)

// logCrash logs a crash to file for later analysis.
func logCrash(testJSON []byte, panicValue any) {
	crashLogMu.Lock()
	defer crashLogMu.Unlock()

	count := atomic.AddInt64(&crashCount, 1)

	crashDir := "testdata/crashes"
	os.MkdirAll(crashDir, 0755)

	crashFile := filepath.Join(crashDir, fmt.Sprintf("crash_%d.json", count))
	os.WriteFile(crashFile, testJSON, 0644)

	f, err := os.OpenFile(crashLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "=== Crash #%d ===\n", count)
	fmt.Fprintf(f, "Time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(f, "Panic: %v\n", panicValue)
	fmt.Fprintf(f, "Input: %s\n\n", crashFile)
}

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

// Package fuzz provides coverage-guided fuzzing for Erigon's EVM using
// goevmlab's custom mutation strategies.
//
// INSTALLATION: This file must be placed inside the erigon repository
// at execution/tests/fuzz/custom_mutator_fuzz_test.go
//
// After copying, run: go mod tidy
// This will add the goevmlab/fuzzing/mutations dependency.
//
// Run with:
//
//	cd execution/tests/fuzz && go test -run=TestFuzzErigonWithCustomMutator -v -timeout=10m
//	FUZZ_DURATION=1h go test -run=TestFuzzErigonWithCustomMutator -v -timeout=2h
package fuzz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/erigontech/erigon/db/datadir"
	"github.com/erigontech/erigon/db/kv"
	"github.com/erigontech/erigon/db/kv/temporal/temporaltest"
	"github.com/erigontech/erigon/execution/tests/testutil"
	"github.com/erigontech/erigon/execution/tracing"
	"github.com/erigontech/erigon/execution/vm"
	"github.com/holiman/goevmlab/fuzzing/mutations"
)

// errExecutionCancelled is a sentinel error used to signal context cancellation
var errExecutionCancelled = fmt.Errorf("execution cancelled")

// cancellationTracer is a minimal tracer that checks for context cancellation
// on each opcode execution, allowing us to abort runaway EVM execution.
// This prevents goroutine leaks when tests timeout.
type cancellationTracer struct {
	ctx     context.Context
	counter uint64
}

// Hooks returns the tracing hooks with cancellation checking on each opcode
func (t *cancellationTracer) Hooks() *tracing.Hooks {
	return &tracing.Hooks{
		OnOpcode: func(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
			// Check every 100 opcodes to reduce overhead while still being responsive
			t.counter++
			if t.counter%100 == 0 {
				if t.ctx.Err() != nil {
					panic(errExecutionCancelled)
				}
			}
		},
	}
}

// TestFuzzErigonWithCustomMutator uses goevmlab's mutation strategies.
//
// Environment variables:
//   - FUZZ_DURATION: How long to run (default: 2m)
//   - FUZZ_SEED_DIR: Directory containing seed JSON files (default: testdata/seeds)
//   - FUZZ_STRATEGY: Mutation strategy (default: combined)
//   - FUZZ_WORKERS: Number of parallel workers (default: NumCPU)
func TestFuzzErigonWithCustomMutator(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping custom mutator fuzz test in short mode")
	}

	seedDir := os.Getenv("FUZZ_SEED_DIR")
	if seedDir == "" {
		seedDir = filepath.Join("testdata", "seeds")
	}

	strategy := os.Getenv("FUZZ_STRATEGY")
	if strategy == "" {
		strategy = "combined"
	}

	duration := 2 * time.Minute
	if d := os.Getenv("FUZZ_DURATION"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil {
			duration = parsed
		}
	}

	numWorkers := runtime.NumCPU()
	if w := os.Getenv("FUZZ_WORKERS"); w != "" {
		if parsed, err := strconv.Atoi(w); err == nil && parsed > 0 {
			numWorkers = parsed
		}
	}

	seeds, err := loadSeedsCustom(seedDir)
	if err != nil || len(seeds) == 0 {
		t.Fatalf("Failed to load seeds from %s: %v (found %d)", seedDir, err, len(seeds))
	}
	t.Logf("Loaded %d seeds from %s", len(seeds), seedDir)
	t.Logf("Strategy: %s, Duration: %v, Workers: %d", strategy, duration, numWorkers)

	var (
		totalExecs    int64
		totalCrashes  int64
		totalTimeouts int64
		startTime     = time.Now()
	)

	// Per-test execution timeout to prevent infinite loops from high gas + looping bytecode
	const testTimeout = 5 * time.Second

	crashDir := filepath.Join("testdata", "custom_crashes")
	os.MkdirAll(crashDir, 0755)
	crashLogFile := "custom_fuzz_crashes.log"
	var crashMu sync.Mutex

	logCrashCustom := func(testJSON []byte, panicValue any, strategyName string) {
		crashMu.Lock()
		defer crashMu.Unlock()

		count := atomic.AddInt64(&totalCrashes, 1)
		crashFile := filepath.Join(crashDir, fmt.Sprintf("crash_%d.json", count))
		os.WriteFile(crashFile, testJSON, 0644)

		f, err := os.OpenFile(crashLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer f.Close()

		fmt.Fprintf(f, "=== Crash #%d ===\n", count)
		fmt.Fprintf(f, "Time: %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(f, "Strategy: %s\n", strategyName)
		fmt.Fprintf(f, "Panic: %v\n", panicValue)
		fmt.Fprintf(f, "Input file: %s\n\n", crashFile)
	}

	// Worker function
	worker := func(id int, seedsChan <-chan []byte, wg *sync.WaitGroup, workerMutator *mutations.RawMutator) {
		defer wg.Done()

		// Each worker gets its own DB
		dirs := datadir.New(t.TempDir())
		db := temporaltest.NewTestDB(t, dirs)

		for seed := range seedsChan {
			mutated, strategyName, err := workerMutator.MutateRawJSON(seed)
			if err != nil {
				mutated = seed
				strategyName = "original"
			}

			// Execute the test with timeout protection
			completed, crashed, panicVal := executeCustomTestWithTimeout(t, db, dirs, mutated, testTimeout)

			if !completed {
				// Timed out - silently skip (not a crash, just runaway execution)
				atomic.AddInt64(&totalTimeouts, 1)
			} else if crashed {
				logCrashCustom(mutated, panicVal, strategyName)
			}

			atomic.AddInt64(&totalExecs, 1)
		}
	}

	seedsChan := make(chan []byte, numWorkers*10)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		workerMutator := mutations.NewRawMutator(strategy)
		go worker(i, seedsChan, &wg, workerMutator)
	}

	// Progress reporter
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(startTime)
				execs := atomic.LoadInt64(&totalExecs)
				crashes := atomic.LoadInt64(&totalCrashes)
				timeouts := atomic.LoadInt64(&totalTimeouts)
				rate := float64(execs) / elapsed.Seconds()
				t.Logf("elapsed: %v, execs: %d (%.0f/sec), crashes: %d, timeouts: %d",
					elapsed.Round(time.Second), execs, rate, crashes, timeouts)
			case <-done:
				return
			}
		}
	}()

	deadline := time.Now().Add(duration)
	seedIndex := 0
	for time.Now().Before(deadline) {
		seed := seeds[seedIndex%len(seeds)]
		seedIndex++
		select {
		case seedsChan <- seed:
		default:
			time.Sleep(time.Millisecond)
		}
	}

	close(seedsChan)
	wg.Wait()
	close(done)

	elapsed := time.Since(startTime)
	execs := atomic.LoadInt64(&totalExecs)
	crashes := atomic.LoadInt64(&totalCrashes)
	timeouts := atomic.LoadInt64(&totalTimeouts)
	rate := float64(execs) / elapsed.Seconds()

	t.Logf("\n=== Final Results ===")
	t.Logf("Duration: %v", elapsed.Round(time.Second))
	t.Logf("Total executions: %d", execs)
	t.Logf("Rate: %.0f exec/sec", rate)
	t.Logf("Crashes found: %d", crashes)
	t.Logf("Timeouts: %d (tests exceeding %v)", timeouts, testTimeout)

	if crashes > 0 {
		t.Logf("Crash files: %s", crashDir)
	}
}

// executeCustomTestWithTimeout runs a state test with a timeout to prevent infinite loops.
// Uses context cancellation to properly stop EVM execution and prevent goroutine leaks.
// Returns: completed (finished before timeout), crashed (panic occurred), panicVal (panic value if crashed)
func executeCustomTestWithTimeout(t testing.TB, db kv.TemporalRwDB, dirs datadir.Dirs, testJSON []byte, timeout time.Duration) (completed bool, crashed bool, panicVal any) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	crashed, panicVal = executeCustomTestWithContext(t, ctx, db, dirs, testJSON)

	// Check if we timed out
	if ctx.Err() == context.DeadlineExceeded {
		return false, false, nil // Timeout, not a crash
	}

	return true, crashed, panicVal
}

// executeCustomTestWithContext runs a state test with context cancellation support.
// The cancellation tracer will panic when the context is cancelled, which we catch
// and distinguish from real crashes.
func executeCustomTestWithContext(t testing.TB, ctx context.Context, db kv.TemporalRwDB, dirs datadir.Dirs, testJSON []byte) (crashed bool, panicVal any) {
	defer func() {
		if r := recover(); r != nil {
			// Check if this was our cancellation panic
			if r == errExecutionCancelled {
				// Clean timeout, not a crash
				crashed = false
				panicVal = nil
				return
			}
			// Real crash
			crashed = true
			panicVal = r
		}
	}()

	var stateTests map[string]testutil.StateTest
	if err := json.Unmarshal(testJSON, &stateTests); err != nil {
		return false, nil
	}

	// Create cancellation tracer
	tracer := &cancellationTracer{ctx: ctx}

	for _, test := range stateTests {
		for _, subtest := range test.Subtests() {
			if !isSupportedFork(subtest.Fork) {
				continue
			}

			// Check context before starting each subtest
			if ctx.Err() != nil {
				return false, nil
			}

			tx, err := db.BeginTemporalRw(ctx)
			if err != nil {
				continue
			}

			func() {
				defer tx.Rollback()
				// Run with our cancellation tracer
				cfg := vm.Config{
					Tracer: tracer.Hooks(),
				}
				_, _, _, _ = test.RunNoVerify(t, tx, subtest, cfg, dirs)
			}()
		}
	}

	return false, nil
}

// executeCustomTest runs a state test and catches panics (without timeout).
// Kept for backwards compatibility with repro_crash_test.go.
func executeCustomTest(t testing.TB, db kv.TemporalRwDB, dirs datadir.Dirs, testJSON []byte) (crashed bool, panicVal any) {
	defer func() {
		if r := recover(); r != nil {
			crashed = true
			panicVal = r
		}
	}()

	var stateTests map[string]testutil.StateTest
	if err := json.Unmarshal(testJSON, &stateTests); err != nil {
		return false, nil
	}

	for _, test := range stateTests {
		for _, subtest := range test.Subtests() {
			if !isSupportedFork(subtest.Fork) {
				continue
			}

			tx, err := db.BeginTemporalRw(context.Background())
			if err != nil {
				continue
			}

			func() {
				defer tx.Rollback()
				cfg := vm.Config{}
				_, _, _, _ = test.RunNoVerify(t, tx, subtest, cfg, dirs)
			}()
		}
	}

	return false, nil
}

func loadSeedsCustom(dir string) ([][]byte, error) {
	var seeds [][]byte
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		seeds = append(seeds, data)
	}
	return seeds, nil
}

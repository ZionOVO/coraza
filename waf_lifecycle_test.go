// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/corazawaf/coraza/v3/internal/memoize"
)

func TestWAFSupportsLifecycleClose(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}
	closer, ok := any(waf).(interface{ Close() error })
	if !ok {
		t.Fatal("WAF must support Close so live reloads can release cache ownership")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewWAFFailureReleasesMemoizedPatterns(t *testing.T) {
	memoize.Reset()
	t.Cleanup(memoize.Reset)

	_, err := NewWAF(NewWAFConfig().
		WithDirectives(`SecRule REQUEST_URI "@pm alpha" "id:1001,phase:1,pass"`).
		WithDirectives(`SecRule`))
	if err == nil {
		t.Fatal("expected invalid directives to fail")
	}

	const probeOwner = ^uint64(0)
	probe := memoize.NewMemoizer(probeOwner)
	t.Cleanup(func() { memoize.Release(probeOwner) })
	compiled := false
	if _, err := probe.Do(testPMCacheKey([]string{"alpha"}), func() (any, error) {
		compiled = true
		return struct{}{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if !compiled {
		t.Fatal("failed WAF retained ownership of a compiled pattern")
	}
}

func TestNewWAFFailureClosesOwnedDebugLog(t *testing.T) {
	debugLogPath := filepath.Join(t.TempDir(), "debug.log")
	_, err := NewWAF(NewWAFConfig().WithDirectives(fmt.Sprintf(`
SecDebugLog %s
SecRule
`, filepath.ToSlash(debugLogPath))))
	if err == nil {
		t.Fatal("expected invalid directives to fail")
	}
	if err := os.Remove(debugLogPath); err != nil {
		t.Fatalf("remove debug log after failed WAF construction: %v", err)
	}
}

func testPMCacheKey(patterns []string) string {
	encoded := make([]byte, 0, len(patterns)*8)
	for _, pattern := range patterns {
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(len(pattern)))
		encoded = append(encoded, pattern...)
	}
	digest := sha256.Sum256(encoded)
	return "pm:ascii-case-insensitive:leftmost-longest:dfa:" + hex.EncodeToString(digest[:])
}

func TestPMFromFileCacheUsesLoadedContents(t *testing.T) {
	first := newPMFromFileWAF(t, "alpha\n")
	defer closeTestWAF(t, first)
	second := newPMFromFileWAF(t, "beta\n")
	defer closeTestWAF(t, second)

	if !wafMatchesURI(t, first, "/alpha") || wafMatchesURI(t, first, "/beta") {
		t.Fatal("first WAF did not use its pattern file")
	}
	if !wafMatchesURI(t, second, "/beta") || wafMatchesURI(t, second, "/alpha") {
		t.Fatal("second WAF reused patterns from another root filesystem")
	}
}

func TestConcurrentWAFReloadsKeepCompiledArtifactsValid(t *testing.T) {
	memoize.Reset()
	t.Cleanup(memoize.Reset)

	const workers = 8
	const reloadsPerWorker = 20
	start := make(chan struct{})
	failures := make(chan error, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer group.Done()
			<-start
			for reload := 0; reload < reloadsPerWorker; reload++ {
				token := "alpha"
				if (worker+reload)%2 != 0 {
					token = "beta"
				}
				if err := exerciseReloadedWAF(token); err != nil {
					failures <- fmt.Errorf("worker %d reload %d: %w", worker, reload, err)
					return
				}
			}
		}(worker)
	}
	close(start)
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func exerciseReloadedWAF(token string) (err error) {
	directives := fmt.Sprintf(`
SecRxPreFilter On
SecRule REQUEST_URI "@pm %s" "id:1001,phase:1,pass"
SecRule REQUEST_URI "@rx ^/%s(?:/.*)?$" "id:1002,phase:1,pass"
`, token, token)
	waf, err := NewWAF(NewWAFConfig().WithDirectives(directives))
	if err != nil {
		return err
	}
	defer func() {
		closer := any(waf).(interface{ Close() error })
		if closeErr := closer.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close WAF: %w", closeErr))
		}
	}()

	tx := waf.NewTransaction()
	defer func() {
		if closeErr := tx.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close transaction: %w", closeErr))
		}
	}()
	tx.ProcessURI("/"+token, "GET", "HTTP/1.1")
	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return fmt.Errorf("request headers interrupted with status %d", interruption.Status)
	}
	if matches := tx.MatchedRules(); len(matches) != 2 {
		return fmt.Errorf("expected two matches, got %d", len(matches))
	}
	return nil
}

func newPMFromFileWAF(t *testing.T, patterns string) WAF {
	t.Helper()
	root := fstest.MapFS{
		"rules.conf": {
			Data: []byte(`SecRule REQUEST_URI "@pmFromFile patterns.data" "id:1001,phase:1,pass"`),
		},
		"patterns.data": {Data: []byte(patterns)},
	}
	waf, err := NewWAF(NewWAFConfig().WithRootFS(root).WithDirectivesFromFile("rules.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return waf
}

func wafMatchesURI(t *testing.T, waf WAF, uri string) bool {
	t.Helper()
	tx := waf.NewTransaction()
	defer func() {
		if err := tx.Close(); err != nil {
			t.Error(err)
		}
	}()
	tx.ProcessURI(uri, "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	return len(tx.MatchedRules()) != 0
}

func closeTestWAF(t *testing.T, waf WAF) {
	t.Helper()
	closer, ok := any(waf).(interface{ Close() error })
	if !ok {
		t.Error("WAF does not expose Close")
		return
	}
	if err := closer.Close(); err != nil {
		t.Error(err)
	}
}

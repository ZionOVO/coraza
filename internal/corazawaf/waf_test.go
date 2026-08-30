// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/types"
)

type closeTrackingWriter struct {
	bytes.Buffer
	closeCalls int
}

func (w *closeTrackingWriter) Close() error {
	w.closeCalls++
	return nil
}

type closeTrackingAuditLogWriter struct {
	initCalls  int
	closeCalls int
}

func (w *closeTrackingAuditLogWriter) Init(plugintypes.AuditLogConfig) error {
	w.initCalls++
	return nil
}

func (*closeTrackingAuditLogWriter) Write(plugintypes.AuditLog) error {
	return nil
}

func (w *closeTrackingAuditLogWriter) Close() error {
	w.closeCalls++
	return nil
}

func TestNewTransaction(t *testing.T) {
	waf := NewWAF()
	waf.RequestBodyAccess = true
	waf.ResponseBodyAccess = true
	waf.RequestBodyLimit = 1044

	tx := waf.NewTransactionWithOptions(Options{ID: "test"})
	if !tx.RequestBodyAccess {
		t.Error("Request body access not enabled")
	}
	if !tx.ResponseBodyAccess {
		t.Error("Response body access not enabled")
	}
	if tx.RequestBodyLimit != 1044 {
		t.Error("Request body limit not set")
	}
	if tx.id != "test" {
		t.Error("ID not set")
	}
	tx = waf.NewTransactionWithOptions(Options{ID: ""})
	if tx.id == "" {
		t.Error("ID not set")
	}
	tx = waf.NewTransaction()
	if tx.id == "" {
		t.Error("ID not set")
	}
}

func TestNewTransactionResetsDetectionOnlyInterruption(t *testing.T) {
	waf := NewWAF()

	// A transaction that recorded a detection-only interruption, then returned
	// to the pool via Close().
	tx := waf.NewTransaction()
	tx.detectionOnlyInterruption = &types.Interruption{Status: 403}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}

	// A subsequent transaction reuses the pooled object and must not inherit it.
	reused := waf.NewTransaction()
	if reused.IsDetectionOnlyInterrupted() {
		t.Error("detectionOnlyInterruption leaked from a pooled transaction into a reused one")
	}
	if err := reused.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSetDebugLogPath(t *testing.T) {
	tests := map[string]struct {
		path string
		w    io.Writer
	}{
		"empty path": {path: "", w: io.Discard},
		"stdout":     {path: "/dev/stdout", w: os.Stdout},
		"stderr":     {path: "/dev/stderr", w: os.Stderr},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			w, closer, err := resolveLogPath(test.path)
			if err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}

			if w != test.w {
				t.Errorf("expected io.Discard, got %T", w)
			}
			if closer != nil {
				t.Errorf("standard debug log target must not be owned, got %T", closer)
			}
		})
	}
}

func TestSetDebugLogPathClosesOwnedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")
	waf := NewWAF()
	if err := waf.SetDebugLogPath(path); err != nil {
		t.Fatal(err)
	}
	if err := waf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove closed debug log: %v", err)
	}
}

func TestReplacingDebugLogClosesOnlyOwnedOutput(t *testing.T) {
	waf := NewWAF()
	owned := &closeTrackingWriter{}
	if err := waf.replaceDebugLogOutput(owned, owned); err != nil {
		t.Fatal(err)
	}
	external := &closeTrackingWriter{}
	waf.SetDebugLogOutput(external)
	if owned.closeCalls != 1 {
		t.Fatalf("owned output close calls: want 1, got %d", owned.closeCalls)
	}
	if err := waf.Close(); err != nil {
		t.Fatal(err)
	}
	if external.closeCalls != 0 {
		t.Fatalf("external output close calls: want 0, got %d", external.closeCalls)
	}
}

func TestCloseClosesInitializedAuditLogWriterOnce(t *testing.T) {
	waf := NewWAF()
	writer := &closeTrackingAuditLogWriter{}
	waf.SetAuditLogWriter(writer)
	if got := waf.AuditLogWriter(); got != writer {
		t.Fatalf("unexpected audit log writer %T", got)
	}
	if err := waf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waf.Close(); err != nil {
		t.Fatal(err)
	}
	if writer.initCalls != 1 {
		t.Fatalf("audit log init calls: want 1, got %d", writer.initCalls)
	}
	if writer.closeCalls != 1 {
		t.Fatalf("audit log close calls: want 1, got %d", writer.closeCalls)
	}
}

func TestReplacingInitializedAuditLogWriterClosesPreviousWriter(t *testing.T) {
	waf := NewWAF()
	first := &closeTrackingAuditLogWriter{}
	waf.SetAuditLogWriter(first)
	if err := waf.InitAuditLogWriter(); err != nil {
		t.Fatal(err)
	}
	second := &closeTrackingAuditLogWriter{}
	waf.SetAuditLogWriter(second)
	if first.closeCalls != 1 {
		t.Fatalf("previous audit log close calls: want 1, got %d", first.closeCalls)
	}
	if err := waf.InitAuditLogWriter(); err != nil {
		t.Fatal(err)
	}
	if err := waf.Close(); err != nil {
		t.Fatal(err)
	}
	if second.closeCalls != 1 {
		t.Fatalf("replacement audit log close calls: want 1, got %d", second.closeCalls)
	}
}

func TestValidate(t *testing.T) {
	testCases := map[string]struct {
		customizer func(*WAF)
		expectErr  bool
	}{
		"default": {
			expectErr:  false,
			customizer: func(w *WAF) {},
		},
		"request body limit less than zero": {
			expectErr:  true,
			customizer: func(w *WAF) { w.RequestBodyLimit = -1 },
		},
		"request body limit greater than 1gib": {
			expectErr:  true,
			customizer: func(w *WAF) { w.RequestBodyLimit = _1gib + 1 },
		},
		"request body in memory limit less than zero": {
			expectErr:  true,
			customizer: func(w *WAF) { w.SetRequestBodyInMemoryLimit(-1) },
		},
		"request body limit less than request body in memory limit": {
			expectErr: true,
			customizer: func(w *WAF) {
				w.RequestBodyLimit = 10
				w.SetRequestBodyInMemoryLimit(11)
			}},
		"response body limit less than zero": {
			expectErr:  true,
			customizer: func(w *WAF) { w.ResponseBodyLimit = -1 },
		},
		"response body limit greater than 1gib": {
			expectErr:  true,
			customizer: func(w *WAF) { w.ResponseBodyLimit = _1gib + 1 },
		},
		"argument limit greater than 0": {
			expectErr:  false,
			customizer: func(w *WAF) { w.ArgumentLimit = 1000 },
		},
		"argument limit less than 0": {
			expectErr:  true,
			customizer: func(w *WAF) { w.ArgumentLimit = -1 },
		},
	}

	if environment.HasAccessToFS {
		testCases["upload keep files on without upload dir"] = struct {
			customizer func(*WAF)
			expectErr  bool
		}{
			expectErr: true,
			customizer: func(w *WAF) {
				w.UploadKeepFiles = types.UploadKeepFilesOn
				w.UploadDir = ""
			},
		}
		testCases["upload keep files relevant only without upload dir"] = struct {
			customizer func(*WAF)
			expectErr  bool
		}{
			expectErr: true,
			customizer: func(w *WAF) {
				w.UploadKeepFiles = types.UploadKeepFilesRelevantOnly
				w.UploadDir = ""
			},
		}
		testCases["upload keep files on with upload dir"] = struct {
			customizer func(*WAF)
			expectErr  bool
		}{
			expectErr: false,
			customizer: func(w *WAF) {
				w.UploadKeepFiles = types.UploadKeepFilesOn
				w.UploadDir = "/tmp"
			},
		}
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			waf := NewWAF()
			tCase.customizer(waf)
			err := waf.Validate()
			if tCase.expectErr {
				if err == nil {
					t.Fatalf("expected error: %s", err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			}
		})
	}
}

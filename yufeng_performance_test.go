// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
)

const yufengBodyLimit = 64 << 10

const portableNormalizePathWin = "yufengBenchmarkNormalizePathWin"

const yufengDirectives = `
Include @coraza.conf-recommended
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyInMemoryLimit 65536
SecRequestBodyLimit 65536
SecRequestBodyNoFilesLimit 65536
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine Off
SecRxPreFilter On
Include @crs-setup.conf.example
Include @owasp_crs/REQUEST-901-INITIALIZATION.conf
Include @owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include @owasp_crs/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include @owasp_crs/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include @owasp_crs/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf
Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include @owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
`

const yufengFullDirectives = `
Include @coraza.conf-recommended
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRequestBodyInMemoryLimit 65536
SecRequestBodyLimit 65536
SecRequestBodyNoFilesLimit 65536
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine Off
SecRxPreFilter On
Include @crs-setup.conf.example
Include @owasp_crs/REQUEST-*.conf
`

type yufengRequest struct {
	method      string
	uri         string
	contentType string
	body        []byte
}

type yufengBenchmarkCase struct {
	name    string
	request yufengRequest
}

type portableRootFS struct {
	fs.FS
}

func init() {
	plugins.RegisterTransformation(portableNormalizePathWin, normalizeRulePath)
}

func (root portableRootFS) Open(name string) (fs.File, error) {
	return root.FS.Open(normalizeFSPath(name))
}

func (root portableRootFS) ReadFile(name string) ([]byte, error) {
	raw, err := fs.ReadFile(root.FS, normalizeFSPath(name))
	if err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(raw, []byte("t:normalizePathWin"), []byte("t:"+portableNormalizePathWin)), nil
}

func (root portableRootFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(root.FS, normalizeFSPath(name))
}

func (root portableRootFS) Glob(pattern string) ([]string, error) {
	return fs.Glob(root.FS, normalizeFSPath(pattern))
}

func normalizeFSPath(name string) string {
	return strings.ReplaceAll(name, `\`, "/")
}

func normalizeRulePath(value string) (string, bool, error) {
	if value == "" {
		return value, false, nil
	}
	slashed := strings.ReplaceAll(value, `\`, "/")
	cleaned := path.Clean(slashed)
	if cleaned == "." {
		return "", true, nil
	}
	if strings.HasSuffix(slashed, "/") {
		cleaned += "/"
	}
	return cleaned, cleaned != value, nil
}

func newYufengWAF(tb testing.TB) coraza.WAF {
	return newYufengWAFWithDirectives(tb, yufengDirectives)
}

func newYufengReferenceWAF(tb testing.TB) coraza.WAF {
	directives := strings.Replace(yufengDirectives, "SecRxPreFilter On", "SecRxPreFilter Off", 1)
	return newYufengWAFWithDirectives(tb, directives)
}

func newYufengFullWAF(tb testing.TB) coraza.WAF {
	return newYufengWAFWithDirectives(tb, yufengFullDirectives)
}

func newYufengFullReferenceWAF(tb testing.TB) coraza.WAF {
	directives := strings.Replace(yufengFullDirectives, "SecRxPreFilter On", "SecRxPreFilter Off", 1)
	return newYufengWAFWithDirectives(tb, directives)
}

func newYufengWAFWithDirectives(tb testing.TB, directives string) coraza.WAF {
	tb.Helper()
	waf := newUnmanagedYufengWAFWithDirectives(tb, directives)
	tb.Cleanup(func() {
		closeYufengWAF(tb, waf)
	})
	return waf
}

func newUnmanagedYufengWAFWithDirectives(tb testing.TB, directives string) coraza.WAF {
	tb.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(portableRootFS{FS: coreruleset.FS}).
		WithDirectives(directives))
	if err != nil {
		tb.Fatal(err)
	}
	return waf
}

func closeYufengWAF(tb testing.TB, waf coraza.WAF) {
	tb.Helper()
	closer, ok := waf.(interface{ Close() error })
	if !ok {
		tb.Error("WAF does not support lifecycle close")
		return
	}
	if err := closer.Close(); err != nil {
		tb.Errorf("close WAF: %v", err)
	}
}

func processYufengRequest(waf coraza.WAF, request yufengRequest) ([]int, error) {
	return processYufengRequestRuleIDs(waf, request, false)
}

func processYufengRequestAllRuleIDs(waf coraza.WAF, request yufengRequest) ([]int, error) {
	return processYufengRequestRuleIDs(waf, request, true)
}

func processYufengRequestRuleIDs(waf coraza.WAF, request yufengRequest, includeAll bool) ([]int, error) {
	tx := waf.NewTransaction()
	closeWithError := func(cause error) error {
		if err := tx.Close(); err != nil {
			return errors.Join(cause, fmt.Errorf("close transaction: %w", err))
		}
		return cause
	}
	tx.ProcessConnection("192.0.2.10", 49152, "192.0.2.20", 443)
	tx.ProcessURI(request.uri, request.method, "HTTP/1.1")
	tx.SetServerName("app.example")
	tx.AddRequestHeader("Host", "app.example")
	tx.AddRequestHeader("User-Agent", "yufeng-edge-benchmark")
	tx.AddRequestHeader("Accept", "*/*")
	if request.contentType != "" {
		tx.AddRequestHeader("Content-Type", request.contentType)
	}
	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		return nil, closeWithError(fmt.Errorf("request headers interrupted with status %d", interruption.Status))
	}
	if len(request.body) > 0 {
		if _, _, err := tx.WriteRequestBody(request.body); err != nil {
			return nil, closeWithError(fmt.Errorf("write request body: %w", err))
		}
	}
	if interruption, err := tx.ProcessRequestBody(); err != nil {
		return nil, closeWithError(fmt.Errorf("process request body: %w", err))
	} else if interruption != nil {
		return nil, closeWithError(fmt.Errorf("request body interrupted with status %d", interruption.Status))
	}

	matched := tx.MatchedRules()
	ids := make([]int, 0, len(matched))
	for _, match := range matched {
		id := match.Rule().ID()
		if includeAll || id >= 930000 && id < 950000 && strings.TrimSpace(match.Message()) != "" {
			ids = append(ids, id)
		}
	}
	tx.ProcessLogging()
	if err := tx.Close(); err != nil {
		return nil, fmt.Errorf("close transaction: %w", err)
	}
	return ids, nil
}

func TestYufengCRSRepresentativeDetections(t *testing.T) {
	waf := newYufengWAF(t)
	referenceWAF := newYufengReferenceWAF(t)
	tests := []struct {
		name     string
		payload  string
		required []int
	}{
		{name: "sql_injection", payload: "id=1+UNION+SELECT+password+FROM+users", required: []int{942100, 942190, 942270, 942360}},
		{name: "cross_site_scripting", payload: "q=<script>alert(1)</script>", required: []int{941100, 941110, 941160, 941390}},
		{name: "local_file_inclusion", payload: "path=/../../etc/passwd", required: []int{930100, 930110, 930120}},
		{name: "command_body", payload: "command=;cat /etc/passwd", required: []int{930120}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := append([]byte(test.payload), bytes.Repeat([]byte("x"), yufengBodyLimit-len(test.payload))...)
			request := yufengRequest{
				method:      "POST",
				uri:         "/upload/blob?page=2",
				contentType: "application/octet-stream",
				body:        body,
			}
			ids, err := processYufengRequest(waf, request)
			if err != nil {
				t.Fatal(err)
			}
			referenceIDs, err := processYufengRequest(referenceWAF, request)
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(ids)
			slices.Sort(referenceIDs)
			if !slices.Equal(ids, referenceIDs) {
				t.Fatalf("accelerated detections differ from the Go backend: accelerated %v, reference %v", ids, referenceIDs)
			}
			for _, required := range test.required {
				if !slices.Contains(ids, required) {
					t.Fatalf("required detection %d is absent from %v", required, ids)
				}
			}
		})
	}
}

func TestYufengFullCRSAcceleratedDetectionsMatchReference(t *testing.T) {
	acceleratedWAF := newYufengFullWAF(t)
	referenceWAF := newYufengFullReferenceWAF(t)
	tests := []struct {
		name          string
		request       yufengRequest
		requireAttack bool
	}{
		{name: "read_no_body", request: yufengRequest{method: "GET", uri: "/api/items?page=2"}},
		{name: "json_4_kib_benign", request: benchmarkJSONRequest(4 << 10)},
		{name: "json_4_kib_attack_head", request: injectYufengSQLAttack(benchmarkJSONRequest(4<<10), true), requireAttack: true},
		{name: "json_4_kib_attack_tail", request: injectYufengSQLAttack(benchmarkJSONRequest(4<<10), false), requireAttack: true},
		{name: "natural_text_64_kib_benign", request: benchmarkNaturalTextRequest(yufengBodyLimit)},
		{name: "natural_text_64_kib_attack_head", request: injectYufengSQLAttack(benchmarkNaturalTextRequest(yufengBodyLimit), true), requireAttack: true},
		{name: "natural_text_64_kib_attack_tail", request: injectYufengSQLAttack(benchmarkNaturalTextRequest(yufengBodyLimit), false), requireAttack: true},
		{name: "base64_64_kib_benign", request: benchmarkBase64Request(yufengBodyLimit)},
		{name: "base64_64_kib_attack_head", request: injectYufengSQLAttack(benchmarkBase64Request(yufengBodyLimit), true), requireAttack: true},
		{name: "base64_64_kib_attack_tail", request: injectYufengSQLAttack(benchmarkBase64Request(yufengBodyLimit), false), requireAttack: true},
		{name: "binary_64_kib_benign", request: benchmarkBinaryRequest(yufengBodyLimit)},
		{name: "binary_64_kib_attack_head", request: injectYufengSQLAttack(benchmarkBinaryRequest(yufengBodyLimit), true), requireAttack: true},
		{name: "binary_64_kib_attack_tail", request: injectYufengSQLAttack(benchmarkBinaryRequest(yufengBodyLimit), false), requireAttack: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			acceleratedIDs, err := processYufengRequestAllRuleIDs(acceleratedWAF, test.request)
			if err != nil {
				t.Fatal(err)
			}
			referenceIDs, err := processYufengRequestAllRuleIDs(referenceWAF, test.request)
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(acceleratedIDs)
			slices.Sort(referenceIDs)
			if !slices.Equal(acceleratedIDs, referenceIDs) {
				t.Fatalf("accelerated detections differ from the Go backend: accelerated %v, reference %v", acceleratedIDs, referenceIDs)
			}
			if test.requireAttack && !containsYufengRuleIDInRange(acceleratedIDs, 942000, 943000) {
				t.Fatalf("SQL injection detection is absent from %v", acceleratedIDs)
			}
		})
	}
}

func containsYufengRuleIDInRange(ids []int, start, end int) bool {
	for _, id := range ids {
		if id >= start && id < end {
			return true
		}
	}
	return false
}

func TestYufengWAFMemoryFootprint(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	waf := newYufengWAF(t)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("WAF_HEAP heap_alloc_delta=%d heap_inuse_delta=%d sys_delta=%d", int64(after.HeapAlloc)-int64(before.HeapAlloc), int64(after.HeapInuse)-int64(before.HeapInuse), int64(after.Sys)-int64(before.Sys))
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kibibytes, parseErr := strconv.ParseUint(fields[1], 10, 64); parseErr == nil {
						t.Logf("WAF_RSS bytes=%d", kibibytes<<10)
					}
				}
				break
			}
		}
	}
	runtime.KeepAlive(waf)
}

func BenchmarkYufengWAFOverlappingReload(b *testing.B) {
	newYufengWAF(b)
	b.ReportAllocs()
	for b.Loop() {
		waf := newUnmanagedYufengWAFWithDirectives(b, yufengDirectives)
		b.StopTimer()
		closeYufengWAF(b, waf)
		b.StartTimer()
	}
}

func BenchmarkYufengWAFColdInitialization(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		waf := newUnmanagedYufengWAFWithDirectives(b, yufengDirectives)
		b.StopTimer()
		closeYufengWAF(b, waf)
		b.StartTimer()
	}
}

func BenchmarkYufengCRSRequestParallel(b *testing.B) {
	waf := newYufengWAF(b)
	for _, test := range yufengBenchmarkRequests() {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.request.body)))
			b.RunParallel(func(pb *testing.PB) {
				var ids []int
				for pb.Next() {
					var err error
					ids, err = processYufengRequest(waf, test.request)
					if err != nil {
						b.Error(err)
						return
					}
				}
				if len(ids) != 0 {
					b.Fatalf("benign request produced detections: %v", ids)
				}
			})
		})
	}
}

func BenchmarkYufengCRSRequestSerial(b *testing.B) {
	waf := newYufengWAF(b)
	for _, test := range yufengBenchmarkRequests() {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.request.body)))
			for range b.N {
				ids, err := processYufengRequest(waf, test.request)
				if err != nil {
					b.Fatal(err)
				}
				if len(ids) != 0 {
					b.Fatalf("benign request produced detections: %v", ids)
				}
			}
		})
	}
}

func BenchmarkYufengCRSMixedSizeParallel(b *testing.B) {
	waf := newYufengWAF(b)
	small := benchmarkJSONRequest(1 << 10)
	large := benchmarkOctetStreamRequest(yufengBodyLimit)
	b.ReportAllocs()
	b.SetBytes(int64((9*len(small.body) + len(large.body)) / 10))
	b.RunParallel(func(pb *testing.PB) {
		iteration := 0
		for pb.Next() {
			request := small
			if iteration%10 == 9 {
				request = large
			}
			ids, err := processYufengRequest(waf, request)
			if err != nil {
				b.Error(err)
				return
			}
			if len(ids) != 0 {
				b.Errorf("benign request produced detections: %v", ids)
				return
			}
			iteration++
		}
	})
}

func BenchmarkYufengCRSAttackPositionParallel(b *testing.B) {
	waf := newYufengWAF(b)
	for _, test := range []struct {
		name    string
		request yufengRequest
	}{
		{name: "head", request: benchmarkAttackRequest(true)},
		{name: "tail", request: benchmarkAttackRequest(false)},
	} {
		b.Run(test.name, func(b *testing.B) {
			ids, err := processYufengRequest(waf, test.request)
			if err != nil {
				b.Fatal(err)
			}
			if len(ids) == 0 {
				b.Fatal("attack benchmark must exercise at least one detection")
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(test.request.body)))
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := processYufengRequest(waf, test.request); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

func BenchmarkYufengFullCRSRequestParallel(b *testing.B) {
	waf := newYufengFullWAF(b)
	for _, test := range []yufengBenchmarkCase{
		{name: "read_no_body", request: yufengRequest{method: "GET", uri: "/api/items?page=2"}},
		{name: "json_4_kib", request: benchmarkJSONRequest(4 << 10)},
		{name: "octet_stream_64_kib", request: benchmarkOctetStreamRequest(yufengBodyLimit)},
		{name: "natural_text_64_kib", request: benchmarkNaturalTextRequest(yufengBodyLimit)},
		{name: "base64_64_kib", request: benchmarkBase64Request(yufengBodyLimit)},
		{name: "binary_64_kib", request: benchmarkBinaryRequest(yufengBodyLimit)},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.request.body)))
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := processYufengRequest(waf, test.request); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

func BenchmarkYufengFullCRSMixedSizeParallel(b *testing.B) {
	waf := newYufengFullWAF(b)
	small := benchmarkJSONRequest(1 << 10)
	for _, test := range []struct {
		name  string
		large yufengRequest
	}{
		{name: "simple_large_body", large: benchmarkOctetStreamRequest(yufengBodyLimit)},
		{name: "natural_text_large_body", large: benchmarkNaturalTextRequest(yufengBodyLimit)},
		{name: "binary_large_body", large: benchmarkBinaryRequest(yufengBodyLimit)},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64((9*len(small.body) + len(test.large.body)) / 10))
			b.RunParallel(func(pb *testing.PB) {
				iteration := 0
				for pb.Next() {
					request := small
					if iteration%10 == 9 {
						request = test.large
					}
					if _, err := processYufengRequest(waf, request); err != nil {
						b.Error(err)
						return
					}
					iteration++
				}
			})
		})
	}
}

func yufengBenchmarkRequests() []yufengBenchmarkCase {
	return []yufengBenchmarkCase{
		{name: "read_no_body", request: yufengRequest{method: "GET", uri: "/api/items?page=2"}},
		{name: "json_1_kib", request: benchmarkJSONRequest(1 << 10)},
		{name: "octet_stream_1_kib", request: benchmarkOctetStreamRequest(1 << 10)},
		{name: "json_4_kib", request: benchmarkJSONRequest(4 << 10)},
		{name: "octet_stream_4_kib", request: benchmarkOctetStreamRequest(4 << 10)},
		{name: "json_12500_bytes", request: benchmarkJSONRequest(12_500)},
		{name: "urlencoded_12500_bytes", request: benchmarkURLEncodedRequest(12_500)},
		{name: "octet_stream_12500_bytes", request: benchmarkOctetStreamRequest(12_500)},
		{name: "json_64_kib", request: benchmarkJSONRequest(yufengBodyLimit)},
		{name: "octet_stream_64_kib", request: benchmarkOctetStreamRequest(yufengBodyLimit)},
		{name: "natural_text_64_kib", request: benchmarkNaturalTextRequest(yufengBodyLimit)},
		{name: "base64_64_kib", request: benchmarkBase64Request(yufengBodyLimit)},
		{name: "binary_64_kib", request: benchmarkBinaryRequest(yufengBodyLimit)},
	}
}

func benchmarkJSONRequest(size int) yufengRequest {
	prefix := []byte(`{"value":"`)
	suffix := []byte(`"}`)
	body := make([]byte, 0, size)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("x"), size-len(prefix)-len(suffix))...)
	body = append(body, suffix...)
	return yufengRequest{method: "POST", uri: "/api/items?page=2", contentType: "application/json", body: body}
}

func benchmarkURLEncodedRequest(size int) yufengRequest {
	prefix := []byte("value=")
	body := bytes.Repeat([]byte("x"), size)
	copy(body, prefix)
	return yufengRequest{method: "POST", uri: "/api/items?page=2", contentType: "application/x-www-form-urlencoded", body: body}
}

func benchmarkOctetStreamRequest(size int) yufengRequest {
	return yufengRequest{
		method:      "POST",
		uri:         "/upload/blob?page=2",
		contentType: "application/octet-stream",
		body:        bytes.Repeat([]byte("x"), size),
	}
}

func benchmarkNaturalTextRequest(size int) yufengRequest {
	phrase := []byte("The quick brown fox crosses the quiet valley while the service records a routine request. ")
	body := bytes.Repeat(phrase, (size+len(phrase)-1)/len(phrase))
	body = body[:size]
	return yufengRequest{method: "POST", uri: "/api/notes?page=2", contentType: "text/plain", body: body}
}

func benchmarkBase64Request(size int) yufengRequest {
	body := bytes.Repeat([]byte("QUJD"), (size+3)/4)
	body = body[:size]
	return yufengRequest{method: "POST", uri: "/upload/blob?page=2", contentType: "application/octet-stream", body: body}
}

func benchmarkBinaryRequest(size int) yufengRequest {
	pattern := []byte{0x01, 0x02, 0x03, 0x04, 0x80, 0x81, 0xfe, 0xff}
	body := bytes.Repeat(pattern, (size+len(pattern)-1)/len(pattern))
	body = body[:size]
	return yufengRequest{method: "POST", uri: "/upload/blob?page=2", contentType: "application/octet-stream", body: body}
}

func benchmarkAttackRequest(atHead bool) yufengRequest {
	payload := []byte("id=1+UNION+SELECT+password+FROM+users")
	body := bytes.Repeat([]byte("x"), yufengBodyLimit)
	position := len(body) - len(payload)
	if atHead {
		position = 0
	}
	copy(body[position:], payload)
	return yufengRequest{method: "POST", uri: "/upload/blob?page=2", contentType: "application/octet-stream", body: body}
}

func injectYufengSQLAttack(request yufengRequest, atHead bool) yufengRequest {
	payload := []byte("id=1+UNION+SELECT+password+FROM+users")
	request.body = slices.Clone(request.body)
	start := 0
	end := len(request.body)
	if request.contentType == "application/json" {
		start = len(`{"value":"`)
		end -= len(`"}`)
	}
	position := start
	if !atHead {
		position = end - len(payload)
	}
	copy(request.body[position:], payload)
	return request
}

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestScanConstructionIsOfflineAndPrepareIsExplicit(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"catalogVersion":"fixture","vulnerabilities":[{"cveID":"CVE-2026-1234"}]}`))
	}))
	defer srv.Close()
	runtime := NewScan(ScanOptions{KEVURL: srv.URL, GoProxy: ""})
	if requests.Load() != 0 {
		t.Fatal("constructor performed IO")
	}
	if runtime.OSV == nil || runtime.NVD == nil || runtime.EPSS == nil || len(runtime.Extractors) == 0 {
		t.Fatal("missing shared provider defaults")
	}
	if err := runtime.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := runtime.KEV.Lookup("CVE-2026-1234"); !ok {
		t.Fatal("KEV not prepared")
	}
}

func TestPrepareDoesNotHideFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "offline", http.StatusServiceUnavailable) }))
	defer srv.Close()
	runtime := NewScan(ScanOptions{KEVURL: srv.URL})
	if err := runtime.Prepare(context.Background()); err == nil {
		t.Fatal("lost KEV error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Prepare(ctx); err == nil {
		t.Fatal("lost cancellation")
	}
}

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/output"
)

// macOS's default temporary directory may itself have a /var alias. Positive
// tests use its real path; symlink-refusal tests create their own explicit links.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func fixtureServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/kev", func(w http.ResponseWriter, r *http.Request) {
		if mode == "kev-error" {
			http.Error(w, "offline", 503)
			return
		}
		_, _ = w.Write([]byte(`{"catalogVersion":"fixture","vulnerabilities":[]}`))
	})
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		if mode == "query-error" {
			http.Error(w, "offline", 503)
			return
		}
		if mode == "timeout" {
			// Drain the request so net/http can observe the client's disconnect.
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			return
		}
		var req struct {
			Queries []json.RawMessage `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			http.Error(w, "bad request", 400)
			return
		}
		results := make([]map[string]any, len(req.Queries))
		for i := range results {
			results[i] = map[string]any{"vulns": []any{}}
			if mode == "vulnerable" || mode == "detail-error" {
				results[i]["vulns"] = []any{map[string]string{"id": "GHSA-fixture", "modified": "2026-01-01T00:00:00Z"}}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("/v1/vulns/GHSA-fixture", func(w http.ResponseWriter, r *http.Request) {
		if mode == "detail-error" {
			http.Error(w, "offline", 503)
			return
		}
		_, _ = w.Write([]byte(`{"id":"GHSA-fixture","modified":"2026-01-01T00:00:00Z","summary":"test advisory","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"PyPI","name":"requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.32.0"}]}]}]}`))
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"data":[]}`)) })
	mux.HandleFunc("/nvd", func(w http.ResponseWriter, r *http.Request) {
		if mode == "nvd-error" {
			http.Error(w, "offline", 503)
			return
		}
		_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func fixtureArgs(t *testing.T, srv *httptest.Server) ([]string, string, string) {
	t.Helper()
	t.Setenv("NVD_API_KEY", "")
	dir, out := realTempDir(t), realTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.19.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"scan", "--path", dir, "--output-dir", out, "--repository", "example/fixture", "--osv-url", srv.URL, "--kev-url", srv.URL + "/kev", "--epss-url", srv.URL + "/epss", "--nvd-url", srv.URL + "/nvd", "--go-proxy", ""}
	return args, dir, out
}

func TestScanCommandWritesArtifactsBeforePolicyFailure(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want int
	}{{"clean", 0}, {"vulnerable", 1}} {
		t.Run(tc.mode, func(t *testing.T) {
			args, dir, out := fixtureArgs(t, fixtureServer(t, tc.mode))
			var stdout, stderr bytes.Buffer
			if got := Execute(context.Background(), args, &stdout, &stderr); got != tc.want {
				t.Fatalf("code=%d stderr=%s", got, &stderr)
			}
			for _, format := range output.Formats() {
				name, _ := output.Filename(format)
				data, err := os.ReadFile(filepath.Join(out, name))
				if err != nil || len(data) == 0 {
					t.Fatalf("missing %s: %v", format, err)
				}
				if format != "markdown" && !json.Valid(data) {
					t.Fatalf("invalid %s", format)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err != nil {
				t.Fatal("checkout deleted")
			}
		})
	}
}

func TestScanCommandErrorsNeverPass(t *testing.T) {
	for _, mode := range []string{"kev-error", "query-error", "detail-error", "timeout", "nvd-error", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			args, dir, out := fixtureArgs(t, fixtureServer(t, mode))
			if mode == "timeout" {
				args = append(args, "--timeout", "20ms")
			}
			if mode == "nvd-error" {
				if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM nginx:1.25.3\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "malformed" {
				if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("not json"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			if got := Execute(context.Background(), args, &stdout, &stderr); got != 2 {
				t.Fatalf("code=%d stderr=%s", got, &stderr)
			}
			if mode == "malformed" || mode == "nvd-error" {
				if _, err := os.Stat(filepath.Join(out, "report.json")); err != nil {
					t.Fatal("partial report not retained")
				}
			}
		})
	}
}

func TestScanValidatesBeforeNetworkAndNeverExecutesTargetScripts(t *testing.T) {
	for _, args := range [][]string{{"scan", "--fail-on", "typo"}, {"scan", "--format", "typo"}, {"scan", "--timeout", "0s"}, {"scan", "--path", "/does-not-exist-cassandra"}} {
		var out bytes.Buffer
		if code := Execute(context.Background(), args, &out, &out); code != 2 {
			t.Fatalf("%v => %d", args, code)
		}
	}
	args, dir, _ := fixtureArgs(t, fixtureServer(t, "clean"))
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"fixture","scripts":{"postinstall":"touch executed"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := Execute(context.Background(), args, &out, &out); code != 0 {
		t.Fatalf("code=%d %s", code, &out)
	}
	if _, err := os.Stat(filepath.Join(dir, "executed")); !os.IsNotExist(err) {
		t.Fatal("target script was executed")
	}
}

func TestPackagedCLIEntryPoint(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "cassandra")
	build := exec.Command("go", "build", "-o", bin, "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	args, _, out := fixtureArgs(t, fixtureServer(t, "vulnerable"))
	cmd := exec.Command(bin, args...)
	data, err := cmd.CombinedOutput()
	if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 1 {
		t.Fatalf("binary: %v\n%s", err, data)
	}
	if _, err := os.Stat(filepath.Join(out, "results.sarif")); err != nil {
		t.Fatal(err)
	}
	version, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "cassandra version") {
		t.Fatalf("version: %s %v", version, err)
	}
}

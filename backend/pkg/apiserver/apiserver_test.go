package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/deploy"
	"github.com/jinho-yoo-jack/vulngraph/pkg/fixer"
	"github.com/jinho-yoo-jack/vulngraph/pkg/git"
	"github.com/jinho-yoo-jack/vulngraph/pkg/github"
	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory/extractor/all"
	"github.com/jinho-yoo-jack/vulngraph/pkg/runner"
	"github.com/jinho-yoo-jack/vulngraph/pkg/server"
	"github.com/jinho-yoo-jack/vulngraph/pkg/storage/boltstore"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/epss"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/kev"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/osv"
)

const apiRoot = "/apis/vulngraph.io/v1alpha1"

// fakeRunner succeeds for every command and records the scripts.
type fakeRunner struct {
	mu      sync.Mutex
	scripts []string
}

func (f *fakeRunner) Run(_ context.Context, spec runner.Spec) (runner.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, spec.Script)
	return runner.Result{Output: "ok"}, nil
}

func (f *fakeRunner) Describe(runner.Spec) string { return "fake runner" }

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newOrigin creates a bare repository with a Python service and a
// Dockerfile running nginx.
func newOrigin(t *testing.T) string {
	root := t.TempDir()
	work, origin := filepath.Join(root, "work"), filepath.Join(root, "origin.git")
	os.MkdirAll(work, 0o755)
	gitCmd(t, root, "init", "-q", "--bare", "-b", "main", origin)
	gitCmd(t, origin, "config", "uploadpack.allowReachableSHA1InWant", "true")
	gitCmd(t, root, "init", "-q", "-b", "main", work)
	os.WriteFile(filepath.Join(work, "requirements.txt"), []byte("Django==3.2.0\nrequests==2.31.0\n"), 0o644)
	os.MkdirAll(filepath.Join(work, "app"), 0o755)
	os.WriteFile(filepath.Join(work, "app", "views.py"), []byte("import django\nimport requests\n"), 0o644)
	os.WriteFile(filepath.Join(work, "Dockerfile"), []byte("FROM nginx:1.25.3-alpine\n"), 0o644)
	gitCmd(t, work, "add", "-A")
	gitCmd(t, work, "commit", "-q", "-m", "init")
	gitCmd(t, work, "push", "-q", origin, "main")
	return origin
}

type fakes struct {
	url       string
	mu        sync.Mutex
	pulls     []github.NewPullRequest
	djangoFix string
}

func newFakes(t *testing.T) *fakes {
	f := &fakes{djangoFix: "3.2.25"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /osv/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Queries []osv.Query }
		json.NewDecoder(r.Body).Decode(&req)
		var results []map[string]any
		for _, q := range req.Queries {
			vulns := []map[string]string{}
			if q.Package.Name == "django" && q.Version == "3.2.0" {
				vulns = append(vulns, map[string]string{"id": "GHSA-test-django", "modified": "2024-01-01T00:00:00Z"})
			}
			results = append(results, map[string]any{"vulns": vulns})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("GET /osv/v1/vulns/GHSA-test-django", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":"GHSA-test-django","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2024-0001"],
			"summary":"SQL injection in Django","details":"Long description.",
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"affected":[{"package":{"ecosystem":"PyPI","name":"Django"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.2"},{"fixed":"%s"}]}]}],
			"references":[{"type":"ADVISORY","url":"https://example.com/advisory"}]}`, f.djangoFix)
	})
	mux.HandleFunc("GET /nvd", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "f5%3Anginx%3A1.25.3") {
			w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
			return
		}
		w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-7347","descriptions":[{"lang":"en","value":"nginx mp4 flaw."}],
			"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H","baseScore":4.7}}]},
			"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionStartIncluding":"1.5.13","versionEndExcluding":"1.27.1"}]}]}]}}]}`))
	})
	mux.HandleFunc("GET /kev", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"catalogVersion":"1","vulnerabilities":[{"cveID":"CVE-2024-0001","dateAdded":"2024-02-01","dueDate":"2024-02-22","requiredAction":"Apply updates"}]}`))
	})
	mux.HandleFunc("GET /epss", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"cve":"CVE-2024-0001","epss":"0.5","percentile":"0.9"}]}`))
	})
	mux.HandleFunc("POST /github/repos/acme/demo/pulls", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var pr github.NewPullRequest
		json.NewDecoder(r.Body).Decode(&pr)
		f.mu.Lock()
		f.pulls = append(f.pulls, pr)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"number":7,"html_url":"https://github.com/acme/demo/pull/7"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

type client struct {
	t    *testing.T
	base string
}

func (c *client) do(method, path string, body, out any) int {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rd = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil {
		if s, ok := out.(*string); ok {
			*s = string(data)
		} else if err := json.Unmarshal(data, out); err != nil {
			c.t.Fatalf("%s %s: decode %q: %v", method, path, data, err)
		}
	}
	return resp.StatusCode
}

func waitFor[T any](t *testing.T, c *client, path string, what string, done func(*T) bool) *T {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var obj T
		c.do(http.MethodGet, path, nil, &obj)
		if done(&obj) {
			return &obj
		}
		time.Sleep(100 * time.Millisecond)
	}
	var obj T
	c.do(http.MethodGet, path, nil, &obj)
	t.Fatalf("timed out waiting for %s: %+v", what, obj)
	return nil
}

func TestEndToEnd(t *testing.T) {
	origin := newOrigin(t)
	fk := newFakes(t)
	dataDir := t.TempDir()
	db, err := boltstore.Open(filepath.Join(dataDir, "vulngraph.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	o := osv.NewClient()
	o.APIURL = fk.url + "/osv"
	n := nvd.NewClient("key")
	n.URL = fk.url + "/nvd"
	k := kev.NewCatalog()
	k.URL = fk.url + "/kev"
	e := epss.NewClient()
	e.URL = fk.url + "/epss"
	gh := github.NewClient("test-token")
	gh.BaseURL = fk.url + "/github"
	fr := &fakeRunner{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const webhookSecret = "s3cret"

	cfg := &Config{
		GenericConfig: &server.Config{Listener: ln, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		ExtraConfig: ExtraConfig{
			DB: db, DataDir: dataDir, OSV: o, NVD: n, KEV: k, EPSS: e,
			Extractors: all.Extractors(all.Options{}), Runner: fr, Docker: &runner.DockerCLI{},
			Toolchains: fixer.DefaultToolchains, GitHub: gh,
			Author:   git.Signature{Name: "bot", Email: "bot@example.com"},
			Deployer: &deploy.Deployer{},
			Feeds: FeedConfig{Enabled: true, OSVInterval: time.Hour, NVDInterval: time.Hour, KEVInterval: time.Hour,
				OSVEcosystems: []string{"PyPI"}, WebhookSecret: webhookSecret},
			CloneURL: func(github.RepoRef) string { return "file://" + origin },
		},
	}
	srv, err := cfg.Complete().New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.GenericAPIServer.PrepareRun().Run(ctx) }()
	defer func() {
		cancel()
		if err := <-runErr; err != nil {
			t.Errorf("server: %v", err)
		}
	}()
	c := &client{t: t, base: "http://" + ln.Addr().String()}

	// --- Scan ---------------------------------------------------------------
	var created v1alpha1.Scan
	if code := c.do(http.MethodPost, apiRoot+"/scans", map[string]any{"spec": map[string]string{"repositoryURL": "https://github.com/acme/demo"}}, &created); code != http.StatusCreated {
		t.Fatalf("create scan: HTTP %d", code)
	}
	var invalid v1alpha1.Status
	if code := c.do(http.MethodPost, apiRoot+"/scans", map[string]any{"spec": map[string]string{"repositoryURL": "https://gitlab.com/a/b"}}, &invalid); code != http.StatusUnprocessableEntity || invalid.Reason != v1alpha1.StatusReasonInvalid {
		t.Errorf("invalid repo: HTTP %d %+v", code, invalid)
	}
	scan := waitFor(t, c, apiRoot+"/scans/"+created.Name, "scan to finish", func(s *v1alpha1.Scan) bool {
		return s.Status.Phase == v1alpha1.ScanSucceeded || s.Status.Phase == v1alpha1.ScanFailed
	})
	if scan.Status.Phase != v1alpha1.ScanSucceeded {
		t.Fatalf("scan failed: %s", scan.Status.Message)
	}
	if s := scan.Status.Summary; s.Vulnerabilities != 2 || s.KnownExploited != 1 || s.Packages != 1 {
		t.Errorf("summary = %+v", s)
	}

	var g v1alpha1.ScanGraph
	c.do(http.MethodGet, apiRoot+"/scans/"+created.Name+"/graph", nil, &g)
	nodes := map[string]v1alpha1.GraphNode{}
	for _, nd := range g.Nodes {
		nodes[nd.ID] = nd
	}
	django := nodes["pkg:pypi/django@3.2.0"]
	if len(django.Findings) != 1 || django.Findings[0].DisplayID != "CVE-2024-0001" || django.Findings[0].FixedVersion != "3.2.25" || !django.Findings[0].KnownExploited {
		t.Errorf("django node = %+v", django)
	}
	if nginx := nodes["pkg:generic/nginx@1.25.3"]; nginx.Kind != v1alpha1.NodeProcess || nginx.Severity != v1alpha1.SeverityMedium {
		t.Errorf("nginx node = %+v", nginx)
	}
	if !nodes["package:app"].OnVulnerablePath || nodes["pkg:pypi/requests@2.31.0"].OnVulnerablePath {
		t.Errorf("vulnerable path marking wrong: app=%v requests=%v", nodes["package:app"].OnVulnerablePath, nodes["pkg:pypi/requests@2.31.0"].OnVulnerablePath)
	}

	var cyclone string
	c.do(http.MethodGet, apiRoot+"/scans/"+created.Name+"/sbom?format=cyclonedx", nil, &cyclone)
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(strings.NewReader(cyclone), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatalf("CycloneDX does not decode: %v", err)
	}
	if bom.SpecVersion != cdx.SpecVersion1_6 || bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 2 || bom.Dependencies == nil {
		t.Errorf("unexpected BOM: spec=%s vulns=%v", bom.SpecVersion, bom.Vulnerabilities)
	}
	var spdx struct {
		SPDXVersion string           `json:"spdxVersion"`
		Packages    []map[string]any `json:"packages"`
	}
	c.do(http.MethodGet, apiRoot+"/scans/"+created.Name+"/sbom?format=spdx", nil, &spdx)
	if spdx.SPDXVersion != "SPDX-2.3" || len(spdx.Packages) < 5 {
		t.Errorf("SPDX = %s with %d packages", spdx.SPDXVersion, len(spdx.Packages))
	}

	var vuln v1alpha1.Vulnerability
	if code := c.do(http.MethodGet, apiRoot+"/vulnerabilities/CVE-2024-0001", nil, &vuln); code != http.StatusOK || vuln.KEV == nil || vuln.EPSS == nil {
		t.Errorf("vulnerability by CVE alias: HTTP %d %+v", code, vuln)
	}

	// --- Remediation --------------------------------------------------------
	var rem v1alpha1.Remediation
	body := map[string]any{"spec": map[string]string{"scanName": created.Name, "vulnerabilityID": "GHSA-test-django", "componentID": "pkg:pypi/django@3.2.0"}}
	if code := c.do(http.MethodPost, apiRoot+"/remediations", body, &rem); code != http.StatusCreated {
		t.Fatalf("create remediation: HTTP %d", code)
	}
	var dup v1alpha1.Status
	if code := c.do(http.MethodPost, apiRoot+"/remediations", body, &dup); code != http.StatusConflict {
		t.Errorf("duplicate remediation: HTTP %d, want 409", code)
	}
	r := waitFor(t, c, apiRoot+"/remediations/"+rem.Name, "review", func(r *v1alpha1.Remediation) bool {
		return r.Status.Phase == v1alpha1.RemediationAwaitingReview || r.Status.Phase.IsTerminal()
	})
	if r.Status.Phase != v1alpha1.RemediationAwaitingReview {
		t.Fatalf("remediation = %s: %s %+v", r.Status.Phase, r.Status.Message, r.Status.Steps)
	}
	if r.Status.ToVersion != "3.2.25" || !strings.HasPrefix(r.Status.Branch, "feature/cve-2024-0001-django") {
		t.Errorf("to=%s branch=%s", r.Status.ToVersion, r.Status.Branch)
	}
	for _, tr := range r.Status.TestResults {
		if tr.Status != v1alpha1.TestPassed {
			t.Errorf("scenario %s %s: %s %s", tr.ID, tr.Title, tr.Status, tr.Detail)
		}
	}
	if len(r.Status.TestResults) != 5 {
		t.Errorf("got %d test results, want 5", len(r.Status.TestResults))
	}

	var docs v1alpha1.RemediationDocs
	c.do(http.MethodGet, apiRoot+"/remediations/"+rem.Name+"/docs", nil, &docs)
	wantDocs := []string{"docs/cve/CVE-2024-0001/vulnerability-details.md", "docs/cve/CVE-2024-0001/remediation.md", "docs/cve/CVE-2024-0001/test-scenarios.md"}
	if len(docs.Files) != 3 {
		t.Fatalf("docs = %+v", docs.Files)
	}
	for i, f := range docs.Files {
		if f.Path != wantDocs[i] {
			t.Errorf("doc %d path = %s, want %s", i, f.Path, wantDocs[i])
		}
	}
	if !strings.Contains(docs.Files[2].Content, "✅ 통과") || !strings.Contains(docs.Files[0].Content, "CISA KEV | **등재**") {
		t.Errorf("docs content not rendered as expected:\n%s\n%s", docs.Files[0].Content, docs.Files[2].Content)
	}
	var diff string
	c.do(http.MethodGet, apiRoot+"/remediations/"+rem.Name+"/diff", nil, &diff)
	if !strings.Contains(diff, "+Django==3.2.25") {
		t.Errorf("diff does not contain the bump:\n%s", diff)
	}

	var bad v1alpha1.Status
	if code := c.do(http.MethodPost, apiRoot+"/remediations/"+rem.Name+"/approval", map[string]any{"approved": true}, &bad); code != http.StatusUnprocessableEntity {
		t.Errorf("approval without reviewer: HTTP %d", code)
	}
	if code := c.do(http.MethodPost, apiRoot+"/remediations/"+rem.Name+"/approval", map[string]any{"approved": true, "reviewer": "alice", "comment": "LGTM"}, nil); code != http.StatusCreated {
		t.Fatalf("approve: HTTP %d", code)
	}
	r = waitFor(t, c, apiRoot+"/remediations/"+rem.Name, "completion", func(r *v1alpha1.Remediation) bool { return r.Status.Phase.IsTerminal() })
	if r.Status.Phase != v1alpha1.RemediationCompleted || r.Status.PullRequestURL != "https://github.com/acme/demo/pull/7" {
		t.Fatalf("remediation = %s: %s", r.Status.Phase, r.Status.Message)
	}
	fk.mu.Lock()
	pr := fk.pulls[0]
	fk.mu.Unlock()
	if pr.Base != "main" || pr.Head != r.Status.Branch || pr.Draft || !strings.Contains(pr.Body, "검토자: alice") {
		t.Errorf("pull request = %+v", pr)
	}
	log := gitCmd(t, origin, "log", "--format=%s", r.Status.Branch)
	if !strings.Contains(log, "fix(security): bump django 3.2.0 → 3.2.25") || !strings.Contains(log, "docs(cve): CVE-2024-0001 test results") {
		t.Errorf("pushed branch history:\n%s", log)
	}
	files := gitCmd(t, origin, "ls-tree", "-r", "--name-only", r.Status.Branch)
	for _, d := range wantDocs {
		if !strings.Contains(files, d) {
			t.Errorf("pushed branch lacks %s", d)
		}
	}

	// --- Webhook -------------------------------------------------------------
	payload := []byte(`{"action":"published","security_advisory":{"ghsa_id":"GHSA-new","cve_id":"CVE-2024-9999","vulnerabilities":[{"package":{"ecosystem":"pip","name":"Django"}}]}}`)
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(payload)
	for _, tc := range []struct {
		sig  string
		want int
	}{{"sha256=" + hex.EncodeToString(mac.Sum(nil)), http.StatusAccepted}, {"sha256=00", http.StatusUnauthorized}} {
		req, _ := http.NewRequest(http.MethodPost, c.base+"/webhooks/github", bytes.NewReader(payload))
		req.Header.Set("X-GitHub-Event", "security_advisory")
		req.Header.Set("X-Hub-Signature-256", tc.sig)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("webhook with signature %q: HTTP %d, want %d", tc.sig[:10], resp.StatusCode, tc.want)
		}
	}
	feed := waitFor(t, c, apiRoot+"/feeds/github-advisories", "webhook feed", func(f *v1alpha1.Feed) bool { return f.Status.Processed == 1 })
	if feed.Status.Matched != 1 {
		t.Errorf("webhook should schedule the scan containing Django, matched=%d", feed.Status.Matched)
	}

	var disc map[string]any
	if code := c.do(http.MethodGet, apiRoot, nil, &disc); code != http.StatusOK || disc["kind"] != "APIResourceList" {
		t.Errorf("discovery: HTTP %d %v", code, disc)
	}
}

package vulndb

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"strings"
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/epss"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/kev"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

// advisories served by the fake OSV API. GHSA and GO records describe the
// same CVE and must be collapsed into one finding.
var advisories = map[string]string{
	"GHSA-jfh8-c2jp-5v3q": `{"id":"GHSA-jfh8-c2jp-5v3q","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2021-44228"],
		"summary":"Remote code injection in Log4j","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
		"affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},
		"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"},{"introduced":"2.16.0"},{"fixed":"2.17.1"}]}]}],
		"database_specific":{"severity":"CRITICAL"}}`,
	"GO-2023-0001": `{"id":"GO-2023-0001","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2023-1111","GHSA-aaaa-bbbb-cccc"],
		"summary":"Go issue","affected":[{"package":{"ecosystem":"Go","name":"github.com/gin-gonic/gin"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.9.1"}]}]}]}`,
	"GHSA-aaaa-bbbb-cccc": `{"id":"GHSA-aaaa-bbbb-cccc","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2023-1111","GO-2023-0001"],
		"summary":"gin issue","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
		"affected":[{"package":{"ecosystem":"Go","name":"github.com/gin-gonic/gin"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.9.1"}]}]}]}`,
}

func fakeServers(t *testing.T) (*osv.Client, *nvd.Client, *kev.Catalog, *epss.Client) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []osv.Query `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var results []map[string]any
		for _, q := range req.Queries {
			var vulns []map[string]string
			switch {
			case q.Package.Name == "org.apache.logging.log4j:log4j-core" && q.Version == "2.14.1":
				vulns = append(vulns, map[string]string{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2024-01-01T00:00:00Z"})
			case q.Package.Name == "github.com/gin-gonic/gin" && q.Version == "1.9.0":
				vulns = append(vulns, map[string]string{"id": "GO-2023-0001", "modified": "2024-01-01T00:00:00Z"},
					map[string]string{"id": "GHSA-aaaa-bbbb-cccc", "modified": "2024-01-01T00:00:00Z"})
			}
			results = append(results, map[string]any{"vulns": vulns})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		body, ok := advisories[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	})
	mux.HandleFunc("GET /nvd", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "f5%3Anginx%3A1.25.3") {
			w.Write([]byte(`{"startIndex":0,"resultsPerPage":0,"totalResults":0,"vulnerabilities":[]}`))
			return
		}
		w.Write([]byte(`{"startIndex":0,"resultsPerPage":1,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-7347","published":"2024-08-14T15:15:00.000",
			"descriptions":[{"lang":"en","value":"NGINX ngx_http_mp4_module flaw. More text."}],
			"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H","baseScore":4.7}}]},
			"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:open_source:*:*:*","versionStartIncluding":"1.5.13","versionEndExcluding":"1.27.1"}]}]}]}}]}`))
	})
	mux.HandleFunc("GET /kev", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"catalogVersion":"1","vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10","dueDate":"2021-12-24","requiredAction":"Apply updates"}]}`))
	})
	mux.HandleFunc("GET /epss", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"cve":"CVE-2021-44228","epss":"0.97","percentile":"0.99"}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	o := osv.NewClient()
	o.APIURL = srv.URL
	n := nvd.NewClient("test-key")
	n.URL = srv.URL + "/nvd"
	k := kev.NewCatalog()
	k.URL = srv.URL + "/kev"
	if _, _, err := k.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := epss.NewClient()
	e.URL = srv.URL + "/epss"
	return o, n, k, e
}

func TestMatch(t *testing.T) {
	t.Run("bolt", func(t *testing.T) { testMatchWithCache(t, newBoltCache(t)) })
	t.Run("memory", func(t *testing.T) { testMatchWithCache(t, NewMemoryCache()) })
}

func testMatchWithCache(t *testing.T, cache AdvisoryCache) {
	o, n, k, e := fakeServers(t)
	m := &Matcher{OSV: o, NVD: n, KEV: k, EPSS: e, Cache: cache, Log: slog.Default()}

	log4j := inventory.NewLibrary(inventory.Maven, "org.apache.logging.log4j:log4j-core", "2.14.1", "pom.xml", true, false)
	gin := inventory.NewLibrary(inventory.Go, "github.com/gin-gonic/gin", "v1.9.0", "go.mod", false, false)
	nginx := &inventory.Component{ID: "pkg:generic/nginx@1.25.3", Name: "nginx", Version: "1.25.3", Ecosystem: inventory.Process, CPEs: []string{"f5:nginx"}, Direct: true}
	inv := &inventory.Inventory{
		Projects:     []*inventory.Project{{ID: "project:go.mod", Manifest: "go.mod"}},
		Components:   []*inventory.Component{log4j, gin, nginx},
		Dependencies: []inventory.Dependency{{From: "project:go.mod", To: gin.ID}},
	}

	res, err := m.Match(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) > 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	type want struct{ vuln, fixed string }
	wants := map[string]want{
		log4j.ID: {"GHSA-jfh8-c2jp-5v3q", "2.15.0"},
		gin.ID:   {"GHSA-aaaa-bbbb-cccc", "v1.9.1"},
		nginx.ID: {"CVE-2024-7347", "1.27.1"},
	}
	if len(res.Findings) != len(wants) {
		t.Fatalf("got %d findings, want %d (aliases not collapsed?): %+v", len(res.Findings), len(wants), res.Findings)
	}
	for _, f := range res.Findings {
		w := wants[f.ComponentID]
		if f.VulnerabilityID != w.vuln || f.FixedVersion != w.fixed {
			t.Errorf("%s: got %s fixed=%s, want %s fixed=%s", f.ComponentID, f.VulnerabilityID, f.FixedVersion, w.vuln, w.fixed)
		}
		if f.Remediation == "" {
			t.Errorf("%s: empty remediation", f.ComponentID)
		}
	}

	l := res.Vulnerabilities["GHSA-jfh8-c2jp-5v3q"]
	if l.CVE != "CVE-2021-44228" || l.CVSS == nil || l.CVSS.Score != 10 || l.KEV == nil || l.EPSS == nil || l.EPSS.Score != 0.97 {
		t.Errorf("log4j advisory not normalised/enriched: %+v", l)
	}
	if ng := res.Vulnerabilities["CVE-2024-7347"]; ng.Severity != "MEDIUM" {
		t.Errorf("nginx severity = %s", ng.Severity)
	}
	if _, ok := m.Cache.Get("CVE-2021-44228"); !ok {
		t.Error("advisory not cached under its CVE alias")
	}
	if raw, _ := m.Cache.Get(l.ID); raw.KEV != nil || raw.EPSS != nil {
		t.Fatal("matching enriched the raw cache")
	}
	sub, err := m.MatchComponents(context.Background(), inv, []string{gin.ID})
	if err != nil || len(sub.Findings) != 1 || sub.Findings[0].ComponentID != gin.ID || sub.Findings[0].FixedVersion != "v1.9.1" {
		t.Fatalf("restricted matching changed: result=%+v error=%v", sub, err)
	}
}

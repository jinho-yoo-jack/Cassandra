package output

import (
	"encoding/json"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/codegraph"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
	"strings"
	"testing"
	"time"
)

func fixture() *report.Report {
	return &report.Report{
		Repository:  v1alpha1.RepositoryInfo{Owner: "example", Name: "fixture", URL: "https://github.com/example/fixture", Commit: "abc"},
		Inventory:   &inventory.Inventory{Projects: []*inventory.Project{{ID: "project", Name: "fixture", Manifest: "package.json"}}, Components: []*inventory.Component{{ID: "dep", Name: "example-lib", Version: "1.0.0", Ecosystem: inventory.NPM, PURL: "pkg:npm/example-lib@1.0.0", Locations: []string{"package.json"}}}},
		Code:        &codegraph.Graph{},
		Match:       &vulndb.Result{Findings: []v1alpha1.Finding{{ComponentID: "dep", VulnerabilityID: "GHSA-fixture", FixedVersion: "2.0.0"}}, Vulnerabilities: map[string]*v1alpha1.Vulnerability{"GHSA-fixture": {ID: "GHSA-fixture", CVE: "CVE-2026-1234", Severity: v1alpha1.SeverityHigh, Summary: "fixture vulnerability", CVSS: &v1alpha1.CVSS{Score: 8.1}}}},
		GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestExistingReportFormats(t *testing.T) {
	for _, format := range []string{"json", "cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			data, err := Encode(fixture(), format)
			if err != nil || !json.Valid(data) {
				t.Fatalf("%s: %s %v", format, data, err)
			}
		})
	}
	if _, err := Encode(fixture(), "typo"); err == nil {
		t.Fatal("unknown format accepted")
	}
	if _, err := Encode(nil, "json"); err == nil {
		t.Fatal("nil report accepted")
	}
}

func TestSARIFMapsFindingsWithoutInventingLineNumbers(t *testing.T) {
	r := fixture()
	data, err := Encode(r, "sarif")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatal("wrong SARIF version")
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)
	if result["ruleId"] != "CVE-2026-1234" || result["level"] != "error" {
		t.Fatalf("result=%v", result)
	}
	loc := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if _, ok := loc["region"]; ok {
		t.Fatal("invented a line number")
	}
	if loc["artifactLocation"].(map[string]any)["uri"] != "package.json" {
		t.Fatal("wrong manifest")
	}
	if len(result["partialFingerprints"].(map[string]any)) == 0 {
		t.Fatal("no stable fingerprint")
	}
	r.Match.Warnings = []string{"NVD offline"}
	data, err = Encode(r, "sarif")
	if err != nil || !strings.Contains(string(data), `"executionSuccessful": false`) {
		t.Fatalf("incomplete SARIF looks successful: %s %v", data, err)
	}
}

func TestMarkdownEscapesRepositoryDataAndListsWarnings(t *testing.T) {
	r := fixture()
	r.Inventory.Components[0].Name = "<script>|[link](https://example.invalid)\nrow"
	r.Match.Warnings = []string{"partial <check>"}
	data, err := Encode(r, "markdown")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "<script>") || strings.Contains(text, "[link](") || !strings.Contains(text, "partial &lt;check&gt;") || !strings.Contains(text, "2.0.0") {
		t.Fatalf("unsafe or missing summary: %s", text)
	}
	for _, format := range Formats() {
		if name, err := Filename(format); err != nil || name == "" {
			t.Fatalf("filename %s: %v", format, err)
		}
	}
}

package remediation

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/version"
)

// Document file names under docs/cve/<id>/.
const (
	DocVulnerabilityDetails = "vulnerability-details.md"
	DocRemediation          = "remediation.md"
	DocTestScenarios        = "test-scenarios.md"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"join":    strings.Join,
	"short":   func(s string) string { return s[:min(len(s), 12)] },
	"date":    func(t time.Time) string { return dateOr(t, "정보 없음") },
	"percent": func(f float64) string { return fmt.Sprintf("%.2f%%", f*100) },
	"sub1":    func(f float64) float64 { return 1 - f },
	"icon":    icon,
}).ParseFS(templateFS, "templates/*.tmpl"))

func icon(s v1alpha1.TestResultStatus) string {
	switch s {
	case v1alpha1.TestPassed:
		return "✅ 통과"
	case v1alpha1.TestFailed:
		return "❌ 실패"
	case v1alpha1.TestSkipped:
		return "⏭ 건너뜀"
	}
	return "⏳ 대기"
}

func dateOr(t time.Time, fallback string) string {
	if t.IsZero() {
		return fallback
	}
	return t.UTC().Format("2006-01-02")
}

// related is another vulnerability of the same component fixed by the bump.
type related struct {
	ID       string
	Severity v1alpha1.Severity
	Fixed    string
}

// scenarioRow is one row of test-scenarios.md.
type scenarioRow struct {
	ID, Title, Method, Expected string
	Status                      v1alpha1.TestResultStatus
	Detail, Duration            string
}

// docData is the input of every template.
type docData struct {
	DocsID         string
	Vuln           *v1alpha1.Vulnerability
	Comp           *inventory.Component
	Finding        v1alpha1.Finding
	From, To       string
	Kind           v1alpha1.RemediationKind
	Branch         string
	BaseBranch     string
	BaseCommit     string
	FixSummary     string
	ChangedFiles   []string
	DependencyPath string
	Related        []related
	Image          string
	Deploy         *v1alpha1.DeployTarget
	Environment    string
	GeneratedAt    string

	Scenarios               []scenarioRow
	Executed                bool
	ExecutedAt              string
	Passed, Failed, Skipped int
	Reviewer, ReviewComment string
}

var unsafeDocChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// docsDir is docs/cve/<id>, with the id sanitised for use as a path.
func docsDir(id string) string {
	return path.Join("docs", "cve", unsafeDocChars.ReplaceAllString(id, "_"))
}

func render(name string, data *docData) (string, error) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name+".tmpl", data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// writeDocs renders the given documents into the working copy and returns
// their repository relative paths.
func writeDocs(root string, data *docData, names ...string) ([]string, error) {
	dir := docsDir(data.DocsID)
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0o755); err != nil {
		return nil, err
	}
	var paths []string
	for _, n := range names {
		content, err := render(n, data)
		if err != nil {
			return nil, fmt.Errorf("render %s: %w", n, err)
		}
		p := path.Join(dir, n)
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(p)), []byte(content), 0o644); err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// setResults copies test results into the scenario rows.
func (d *docData) setResults(results []v1alpha1.TestResult, executedAt time.Time) {
	byID := map[string]v1alpha1.TestResult{}
	for _, r := range results {
		byID[r.ID] = r
	}
	d.Passed, d.Failed, d.Skipped = 0, 0, 0
	for i := range d.Scenarios {
		r, ok := byID[d.Scenarios[i].ID]
		if !ok {
			continue
		}
		d.Scenarios[i].Status, d.Scenarios[i].Detail, d.Scenarios[i].Duration = r.Status, r.Detail, r.Duration
		switch r.Status {
		case v1alpha1.TestPassed:
			d.Passed++
		case v1alpha1.TestFailed:
			d.Failed++
		default:
			d.Skipped++
		}
	}
	d.Executed, d.ExecutedAt = true, executedAt.UTC().Format(time.RFC3339)
}

// relatedFindings lists other vulnerabilities of the component whose fix is
// at or below the target version.
func relatedFindings(sc *stepContext, target string) []related {
	var out []related
	for _, f := range sc.report.FindingsFor(sc.comp.ID) {
		if f.VulnerabilityID == sc.vuln.ID || f.FixedVersion == "" {
			continue
		}
		if version.Compare(string(sc.comp.Ecosystem), strings.TrimPrefix(f.FixedVersion, "v"), strings.TrimPrefix(target, "v")) <= 0 {
			v := sc.report.Match.Vulnerabilities[f.VulnerabilityID]
			out = append(out, related{ID: v.DisplayID(), Severity: v.Severity, Fixed: f.FixedVersion})
		}
	}
	return out
}

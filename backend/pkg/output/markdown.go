package output

import (
	"fmt"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"html"
	"strings"
)

// Escape untrusted repository/advisory text before placing it in Markdown.
func markdownText(s string) string {
	s = html.EscapeString(s)
	return strings.NewReplacer("\\", "\\\\", "|", "\\|", "[", "\\[", "]", "\\]", "`", "\\`", "*", "\\*", "_", "\\_", "\r", " ", "\n", " ").Replace(s)
}

func encodeMarkdown(r *report.Report) ([]byte, error) {
	var b strings.Builder
	s := r.Summary()
	fmt.Fprintf(&b, "## Cassandra scan\n\nRepository: %s/%s\n\n%d projects · %d components · %d vulnerabilities · %d known exploited\n\n", markdownText(r.Repository.Owner), markdownText(r.Repository.Name), s.Projects, s.Components, s.Vulnerabilities, s.KnownExploited)
	if len(r.Match.Warnings) > 0 {
		b.WriteString("### Incomplete scan\n\n")
		for _, w := range r.Match.Warnings {
			fmt.Fprintf(&b, "- %s\n", markdownText(w))
		}
		b.WriteString("\n")
	}
	if len(r.Inventory.Projects) == 0 {
		b.WriteString("**No supported manifests found. This is not a clean security assessment.**\n\n")
	}
	b.WriteString("| Vulnerability | Component | Severity | Fixed version |\n|---|---|---|---|\n")
	// Keep the Actions summary bounded; machine-readable formats retain all findings.
	for i, f := range r.Match.Findings {
		if i == 200 {
			fmt.Fprintf(&b, "\nShowing 200 of %d findings. See the report artifact for all results.\n", len(r.Match.Findings))
			break
		}
		v, c := r.Match.Vulnerabilities[f.VulnerabilityID], r.Inventory.Component(f.ComponentID)
		fmt.Fprintf(&b, "| %s | %s@%s | %s | %s |\n", markdownText(v.DisplayID()), markdownText(c.Name), markdownText(c.Version), markdownText(string(v.Severity)), markdownText(f.FixedVersion))
	}
	return []byte(b.String()), nil
}

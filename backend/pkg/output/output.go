// Package output renders reports independently of scanning and CI policy.
package output

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/sbom"
)

type encoder struct {
	filename string
	encode   func(*report.Report) ([]byte, error)
}

// Encoders are stateless strategies. Adding a format changes this registry,
// not the CLI's scan, policy or file-handling orchestration.
var encoders = map[string]encoder{
	"markdown":  {"summary.md", encodeMarkdown},
	"sarif":     {"results.sarif", encodeSARIF},
	"json":      {"report.json", func(r *report.Report) ([]byte, error) { return json.MarshalIndent(r, "", "  ") }},
	"cyclonedx": {"sbom.cyclonedx.json", func(r *report.Report) ([]byte, error) { return sbom.Encode(r, sbom.CycloneDX) }},
	"spdx":      {"sbom.spdx.json", func(r *report.Report) ([]byte, error) { return sbom.Encode(r, sbom.SPDX) }},
}

func Formats() []string {
	formats := make([]string, 0, len(encoders))
	for name := range encoders {
		formats = append(formats, name)
	}
	slices.Sort(formats)
	return formats
}

func Filename(format string) (string, error) {
	e, ok := encoders[format]
	if !ok {
		return "", fmt.Errorf("unsupported output format %q", format)
	}
	return e.filename, nil
}

func Encode(r *report.Report, format string) ([]byte, error) {
	e, ok := encoders[format]
	if !ok {
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
	if r == nil || r.Inventory == nil || r.Code == nil || r.Match == nil {
		return nil, fmt.Errorf("cannot encode an incomplete report")
	}
	for _, f := range r.Match.Findings {
		if r.Inventory.Component(f.ComponentID) == nil || r.Match.Vulnerabilities[f.VulnerabilityID] == nil {
			return nil, fmt.Errorf("finding references a missing component or advisory")
		}
	}
	return e.encode(r)
}

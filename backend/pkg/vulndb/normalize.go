// Package vulndb matches inventories against OSV and NVD and normalises
// their records into v1alpha1.Vulnerability.
package vulndb

import (
	"slices"
	"strings"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/version"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/cvss"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

// EcosystemCPE is the AffectedPackage ecosystem of NVD CPE ranges.
const EcosystemCPE = "CPE"

// SeverityFromScore maps a CVSS base score to its qualitative rating.
func SeverityFromScore(score float64) v1alpha1.Severity {
	switch {
	case score >= 9:
		return v1alpha1.SeverityCritical
	case score >= 7:
		return v1alpha1.SeverityHigh
	case score >= 4:
		return v1alpha1.SeverityMedium
	case score > 0:
		return v1alpha1.SeverityLow
	default:
		return v1alpha1.SeverityNone
	}
}

func severityFromLabel(s string) v1alpha1.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return v1alpha1.SeverityCritical
	case "HIGH":
		return v1alpha1.SeverityHigh
	case "MODERATE", "MEDIUM":
		return v1alpha1.SeverityMedium
	case "LOW":
		return v1alpha1.SeverityLow
	}
	return v1alpha1.SeverityUnknown
}

// FromOSV converts an OSV record.
func FromOSV(o *osv.Vulnerability) *v1alpha1.Vulnerability {
	v := &v1alpha1.Vulnerability{
		TypeMeta: v1alpha1.NewTypeMeta(v1alpha1.KindVulnerability),
		ID:       o.ID, Aliases: o.Aliases, Summary: o.Summary, Details: o.Details,
		Published: o.Published, Modified: o.Modified, Withdrawn: o.Withdrawn,
		CWEs: o.DatabaseSpecific.CWEIDs, Source: "osv", Severity: v1alpha1.SeverityUnknown,
	}
	v.CVE = primaryCVE(o.ID, o.Aliases)

	severities := o.Severity
	for _, a := range o.Affected {
		severities = append(severities, a.Severity...)
	}
	for _, s := range severities {
		if s.Type != "CVSS_V3" {
			continue
		}
		if score, err := cvss.Score3(s.Score); err == nil {
			v.CVSS = &v1alpha1.CVSS{Version: "3.1", Vector: s.Score, Score: score}
			v.Severity = SeverityFromScore(score)
			break
		}
	}
	if v.CVSS == nil {
		for _, s := range severities {
			if s.Type == "CVSS_V4" {
				// No v4 calculator: keep the vector, rate from the label.
				v.CVSS = &v1alpha1.CVSS{Version: "4.0", Vector: s.Score}
				break
			}
		}
		if l := severityFromLabel(o.DatabaseSpecific.Severity); l != v1alpha1.SeverityUnknown {
			v.Severity = l
		}
	}

	for _, r := range o.References {
		v.References = append(v.References, v1alpha1.Reference{Type: r.Type, URL: r.URL})
	}
	for _, a := range o.Affected {
		ap := v1alpha1.AffectedPackage{Ecosystem: a.Package.Ecosystem, Name: a.Package.Name}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			ap.Ranges = append(ap.Ranges, rangesFromEvents(r.Events)...)
		}
		v.Affected = append(v.Affected, ap)
	}
	return v
}

func rangesFromEvents(events []osv.Event) []v1alpha1.AffectedRange {
	var (
		out []v1alpha1.AffectedRange
		cur *v1alpha1.AffectedRange
	)
	for _, e := range events {
		switch {
		case e.Introduced != "":
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &v1alpha1.AffectedRange{Introduced: e.Introduced}
		case e.Fixed != "" && cur != nil:
			cur.Fixed = e.Fixed
			out = append(out, *cur)
			cur = nil
		case e.LastAffected != "" && cur != nil:
			cur.LastAffected = e.LastAffected
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

func primaryCVE(id string, aliases []string) string {
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return ""
}

// FromNVD converts an NVD CVE record.
func FromNVD(c *nvd.CVE) *v1alpha1.Vulnerability {
	v := &v1alpha1.Vulnerability{
		TypeMeta: v1alpha1.NewTypeMeta(v1alpha1.KindVulnerability),
		ID:       c.ID, CVE: c.ID, Source: "nvd", Severity: v1alpha1.SeverityUnknown,
	}
	v.Published, _ = time.Parse("2006-01-02T15:04:05.000", c.Published)
	v.Modified, _ = time.Parse("2006-01-02T15:04:05.000", c.LastModified)
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			v.Details = d.Value
			v.Summary = firstSentence(d.Value)
			break
		}
	}
	// Prefer the NVD primary assessment of the newest scored version; old
	// CVEs are only scored with CVSS v2.
	for _, metrics := range [][]nvd.Metric{c.Metrics.V31, c.Metrics.V30, c.Metrics.V40, c.Metrics.V2} {
		if len(metrics) == 0 {
			continue
		}
		m := metrics[0]
		for _, cand := range metrics {
			if cand.Type == "Primary" {
				m = cand
				break
			}
		}
		v.CVSS = &v1alpha1.CVSS{Version: m.CVSSData.Version, Vector: m.CVSSData.VectorString, Score: m.CVSSData.BaseScore}
		v.Severity = SeverityFromScore(m.CVSSData.BaseScore)
		if m.CVSSData.Version == "2.0" {
			// v2 has no Critical band; use NVD's own rating.
			v.Severity = severityFromLabel(m.BaseSeverity)
		}
		break
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") && !slices.Contains(v.CWEs, d.Value) {
				v.CWEs = append(v.CWEs, d.Value)
			}
		}
	}
	for _, r := range c.References {
		typ := "WEB"
		if slices.Contains(r.Tags, "Patch") {
			typ = "FIX"
		} else if slices.Contains(r.Tags, "Vendor Advisory") {
			typ = "ADVISORY"
		}
		v.References = append(v.References, v1alpha1.Reference{Type: typ, URL: r.URL})
	}
	byProduct := map[string]*v1alpha1.AffectedPackage{}
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			if n.Negate {
				continue
			}
			for _, m := range n.CPEMatch {
				vendorProduct, ver, ok := splitCPE(m.Criteria)
				if !m.Vulnerable || !ok {
					continue
				}
				ap, ok := byProduct[vendorProduct]
				if !ok {
					ap = &v1alpha1.AffectedPackage{Ecosystem: EcosystemCPE, Name: vendorProduct}
					byProduct[vendorProduct] = ap
				}
				r := v1alpha1.AffectedRange{
					Introduced:   firstNonEmpty(m.VersionStartIncluding, m.VersionStartExcluding),
					Fixed:        m.VersionEndExcluding,
					LastAffected: m.VersionEndIncluding,
				}
				if ver != "*" && ver != "-" {
					r = v1alpha1.AffectedRange{Introduced: ver, LastAffected: ver}
				}
				ap.Ranges = append(ap.Ranges, r)
			}
		}
	}
	for _, ap := range byProduct {
		v.Affected = append(v.Affected, *ap)
	}
	slices.SortFunc(v.Affected, func(a, b v1alpha1.AffectedPackage) int { return strings.Compare(a.Name, b.Name) })
	return v
}

// splitCPE returns "vendor:product" and the version of a CPE 2.3 name.
func splitCPE(cpe string) (string, string, bool) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return "", "", false
	}
	return parts[3] + ":" + parts[4], parts[5], true
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 && i < 200 {
		return s[:i+1]
	}
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// affectedName returns the name used to match AffectedPackage entries
// against a component.
func affectedNames(c *inventory.Component) (eco string, names []string) {
	switch c.Ecosystem {
	case inventory.Process:
		return EcosystemCPE, c.CPEs
	case inventory.PyPI:
		return string(c.Ecosystem), []string{inventory.NormalizePyPI(c.Name)}
	default:
		return string(c.Ecosystem), []string{c.Name}
	}
}

// FixedVersion returns the lowest version of c that is not affected by v:
// the end of the range containing c.Version, or else the smallest fix above
// it. It returns "" when no fix exists.
func FixedVersion(v *v1alpha1.Vulnerability, c *inventory.Component) string {
	eco, names := affectedNames(c)
	cur := strings.TrimPrefix(c.Version, "v")
	vcmp := func(a, b string) int { return version.Compare(string(c.Ecosystem), a, b) }

	var candidates []string
	for _, ap := range v.Affected {
		name := ap.Name
		if ap.Ecosystem == string(inventory.PyPI) {
			name = inventory.NormalizePyPI(name)
		}
		if ap.Ecosystem != eco || !slices.Contains(names, name) {
			continue
		}
		for _, r := range ap.Ranges {
			if r.Fixed == "" {
				continue
			}
			fixed := strings.TrimPrefix(r.Fixed, "v")
			introducedOK := r.Introduced == "" || r.Introduced == "0" || vcmp(strings.TrimPrefix(r.Introduced, "v"), cur) <= 0
			if introducedOK && vcmp(cur, fixed) < 0 {
				return restorePrefix(c, fixed)
			}
			if vcmp(fixed, cur) > 0 {
				candidates = append(candidates, fixed)
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	slices.SortFunc(candidates, vcmp)
	return restorePrefix(c, candidates[0])
}

// restorePrefix keeps Go's "v" prefix, which go get requires.
func restorePrefix(c *inventory.Component, v string) string {
	if c.Ecosystem == inventory.Go && c.Name != "stdlib" && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

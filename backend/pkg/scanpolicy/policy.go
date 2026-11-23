// Package scanpolicy applies CI decisions independently of analysis and output.
package scanpolicy

import (
	"fmt"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"strings"
)

type Policy struct {
	threshold v1alpha1.Severity
	disabled  bool
}
type Decision struct {
	ExitCode int
	Message  string
}

// New validates before network work. "none" disables findings gating, never
// inspection-error gating. Unknown severity blocks every enabled threshold.
func New(threshold string) (Policy, error) {
	switch threshold {
	case "none":
		return Policy{disabled: true}, nil
	case "low", "medium", "high", "critical":
		return Policy{threshold: v1alpha1.Severity(strings.ToUpper(threshold))}, nil
	default:
		return Policy{}, fmt.Errorf("fail-on must be none, low, medium, high or critical, got %q", threshold)
	}
}

func (p Policy) Evaluate(r *report.Report) Decision {
	if r == nil || r.Inventory == nil || r.Match == nil {
		return Decision{2, "scan returned no complete report"}
	}
	if len(r.Match.Warnings) > 0 {
		return Decision{2, "scan incomplete: " + strings.Join(r.Match.Warnings, "; ")}
	}
	if len(r.Inventory.Projects) == 0 {
		return Decision{2, "no supported manifests found; this is not a clean security assessment"}
	}
	for _, f := range r.Match.Findings {
		v := r.Match.Vulnerabilities[f.VulnerabilityID]
		if v == nil {
			return Decision{2, "scan contains a finding without advisory details"}
		}
		if !p.disabled && (v.Severity.Rank() == 0 || v.Severity.Rank() >= p.threshold.Rank()) {
			return Decision{1, "vulnerability policy failed: " + v.DisplayID() + " (" + string(v.Severity) + ")"}
		}
	}
	return Decision{0, "scan complete; vulnerability policy passed"}
}

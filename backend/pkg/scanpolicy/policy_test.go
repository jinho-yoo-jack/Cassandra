package scanpolicy

import (
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
	"testing"
)

func TestPolicySeparatesFindingsFromIncompleteScans(t *testing.T) {
	for _, tc := range []struct {
		name, threshold string
		severity        v1alpha1.Severity
		warnings        []string
		want            int
	}{
		{"below threshold", "high", v1alpha1.SeverityMedium, nil, 0},
		{"at threshold", "high", v1alpha1.SeverityHigh, nil, 1},
		{"unknown is not safe", "critical", v1alpha1.SeverityUnknown, nil, 1},
		{"disabled gate", "none", v1alpha1.SeverityCritical, nil, 0},
		{"incomplete still fails", "none", v1alpha1.SeverityLow, []string{"NVD offline"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := New(tc.threshold)
			if err != nil {
				t.Fatal(err)
			}
			r := &report.Report{Inventory: &inventory.Inventory{Projects: []*inventory.Project{{ID: "p"}}}, Match: &vulndb.Result{Warnings: tc.warnings, Findings: []v1alpha1.Finding{{VulnerabilityID: "v"}}, Vulnerabilities: map[string]*v1alpha1.Vulnerability{"v": {ID: "v", Severity: tc.severity}}}}
			if got := policy.Evaluate(r); got.ExitCode != tc.want {
				t.Fatalf("got %+v want code %d", got, tc.want)
			}
		})
	}
	if _, err := New("typo"); err == nil {
		t.Fatal("invalid threshold accepted")
	}
	policy, _ := New("none")
	if got := policy.Evaluate(&report.Report{Inventory: &inventory.Inventory{}, Match: &vulndb.Result{}}); got.ExitCode != 2 {
		t.Fatal("empty unsupported tree treated as clean")
	}
}

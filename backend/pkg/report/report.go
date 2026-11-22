// Package report holds the full result of a scan. Reports are too large to
// be API objects; the Scan status carries a summary and subresources render
// graphs and SBOMs from the stored report.
package report

import (
	"time"

	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/codegraph"
	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
	"github.com/jinho-yoo-jack/vulngraph/pkg/storage/boltstore"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb"
)

// Report is the stored outcome of a scan.
type Report struct {
	Repository  v1alpha1.RepositoryInfo `json:"repository"`
	Inventory   *inventory.Inventory    `json:"inventory"`
	Code        *codegraph.Graph        `json:"code"`
	Match       *vulndb.Result          `json:"match"`
	GeneratedAt time.Time               `json:"generatedAt"`
	EvaluatedAt time.Time               `json:"evaluatedAt"`
}

// Summary aggregates the report for the Scan status.
func (r *Report) Summary() *v1alpha1.ScanSummary {
	s := &v1alpha1.ScanSummary{
		Projects:   len(r.Inventory.Projects),
		Packages:   len(r.Code.Packages),
		Components: len(r.Inventory.Components),
		BySeverity: map[v1alpha1.Severity]int{},
	}
	vulnerable := map[string]bool{}
	counted := map[string]bool{}
	for _, f := range r.Match.Findings {
		vulnerable[f.ComponentID] = true
		v := r.Match.Vulnerabilities[f.VulnerabilityID]
		if counted[v.DisplayID()] {
			continue
		}
		counted[v.DisplayID()] = true
		s.Vulnerabilities++
		s.BySeverity[v.Severity]++
		if v.KEV != nil {
			s.KnownExploited++
		}
	}
	s.VulnerableComponents = len(vulnerable)
	return s
}

// FindingsFor returns the findings of one component.
func (r *Report) FindingsFor(componentID string) []v1alpha1.Finding {
	var out []v1alpha1.Finding
	for _, f := range r.Match.Findings {
		if f.ComponentID == componentID {
			out = append(out, f)
		}
	}
	return out
}

// Finding returns the finding binding a component to a vulnerability.
func (r *Report) Finding(componentID, vulnerabilityID string) (v1alpha1.Finding, bool) {
	for _, f := range r.Match.Findings {
		if f.ComponentID == componentID && f.VulnerabilityID == vulnerabilityID {
			return f, true
		}
	}
	return v1alpha1.Finding{}, false
}

// Store persists reports by scan name.
type Store struct {
	blobs *boltstore.Blobs
}

// NewStore returns a report store.
func NewStore(blobs *boltstore.Blobs) *Store { return &Store{blobs: blobs} }

// Get loads a report.
func (s *Store) Get(name string) (*Report, error) {
	var r Report
	if err := s.blobs.Get(name, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Put saves a report.
func (s *Store) Put(name string, r *Report) error { return s.blobs.Put(name, r) }

// Delete removes a report.
func (s *Store) Delete(name string) error { return s.blobs.Delete(name) }

// Names lists every stored report.
func (s *Store) Names() ([]string, error) { return s.blobs.Keys() }

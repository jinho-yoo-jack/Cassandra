package vulndb

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/epss"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/kev"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/osv"
)

// osvEcosystems are the inventory ecosystems OSV can match.
var osvEcosystems = map[inventory.Ecosystem]bool{
	inventory.Go: true, inventory.NPM: true, inventory.PyPI: true, inventory.Maven: true,
	inventory.CratesIO: true, inventory.RubyGems: true, inventory.Packagist: true,
}

// Matcher finds the vulnerabilities of an inventory.
type Matcher struct {
	OSV   *osv.Client
	NVD   *nvd.Client
	KEV   *kev.Catalog
	EPSS  *epss.Client
	Cache *Cache
	Log   *slog.Logger
}

// Result is the outcome of matching one inventory.
type Result struct {
	Vulnerabilities map[string]*v1alpha1.Vulnerability `json:"vulnerabilities"`
	Findings        []v1alpha1.Finding                 `json:"findings"`
	// Warnings are partial failures, e.g. NVD being unavailable.
	Warnings []string `json:"warnings,omitempty"`
}

// Match queries OSV for libraries and NVD for processes, de-duplicates
// aliases per component, enriches with KEV and EPSS and computes fixes.
func (m *Matcher) Match(ctx context.Context, inv *inventory.Inventory) (*Result, error) {
	res := &Result{Vulnerabilities: map[string]*v1alpha1.Vulnerability{}}
	perComponent := map[string][]*v1alpha1.Vulnerability{}

	libs, err := m.matchLibraries(ctx, inv)
	if err != nil {
		return nil, err
	}
	for id, vs := range libs {
		perComponent[id] = vs
	}
	procs, warnings := m.matchProcesses(ctx, inv)
	res.Warnings = append(res.Warnings, warnings...)
	for id, vs := range procs {
		perComponent[id] = vs
	}

	for compID, vulns := range perComponent {
		for _, v := range dedupe(vulns) {
			res.Vulnerabilities[v.ID] = v
			res.Findings = append(res.Findings, v1alpha1.Finding{ComponentID: compID, VulnerabilityID: v.ID})
		}
	}
	if err := m.Enrich(ctx, res.Vulnerabilities); err != nil {
		res.Warnings = append(res.Warnings, "EPSS: "+err.Error())
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		c, v := inv.Component(f.ComponentID), res.Vulnerabilities[f.VulnerabilityID]
		f.FixedVersion = FixedVersion(v, c)
		f.Remediation = Guidance(inv, c, v, f.FixedVersion)
	}
	slices.SortFunc(res.Findings, func(a, b v1alpha1.Finding) int {
		if c := strings.Compare(a.ComponentID, b.ComponentID); c != 0 {
			return c
		}
		return strings.Compare(a.VulnerabilityID, b.VulnerabilityID)
	})
	return res, nil
}

// MatchComponents is Match restricted to the given component IDs, used to
// verify a remediation without rescanning the whole inventory.
func (m *Matcher) MatchComponents(ctx context.Context, inv *inventory.Inventory, ids []string) (*Result, error) {
	sub := &inventory.Inventory{Projects: inv.Projects, Dependencies: inv.Dependencies}
	for _, id := range ids {
		if c := inv.Component(id); c != nil {
			sub.Components = append(sub.Components, c)
		}
	}
	return m.Match(ctx, sub)
}

func osvQuery(c *inventory.Component) osv.Query {
	v := c.Version
	if c.Ecosystem == inventory.Go {
		v = strings.TrimPrefix(v, "v")
	}
	return osv.Query{Package: osv.Package{Name: c.Name, Ecosystem: string(c.Ecosystem)}, Version: v}
}

func (m *Matcher) matchLibraries(ctx context.Context, inv *inventory.Inventory) (map[string][]*v1alpha1.Vulnerability, error) {
	var (
		comps   []*inventory.Component
		queries []osv.Query
	)
	for _, c := range inv.Components {
		if osvEcosystems[c.Ecosystem] && c.Version != "" {
			comps = append(comps, c)
			queries = append(queries, osvQuery(c))
		}
	}
	if len(queries) == 0 {
		return nil, nil
	}
	refs, err := m.OSV.QueryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	// Fetch every distinct advisory once, reusing cached records that are
	// at least as new as what querybatch reported.
	latest := map[string]osv.VulnRef{}
	for _, rs := range refs {
		for _, r := range rs {
			if cur, ok := latest[r.ID]; !ok || r.Modified.After(cur.Modified) {
				latest[r.ID] = r
			}
		}
	}
	var (
		mu      sync.Mutex
		details = map[string]*v1alpha1.Vulnerability{}
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8)
	for id, ref := range latest {
		g.Go(func() error {
			v, err := m.Advisory(gctx, id, ref)
			if err != nil {
				m.Log.Warn("[vulndb] Fetch advisory failed", "id", id, "err", err)
				return nil
			}
			mu.Lock()
			details[id] = v
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	out := map[string][]*v1alpha1.Vulnerability{}
	for i, rs := range refs {
		for _, r := range rs {
			if v, ok := details[r.ID]; ok && v.Withdrawn == nil {
				out[comps[i].ID] = append(out[comps[i].ID], v)
			}
		}
	}
	return out, nil
}

// Advisory returns an OSV record, from the cache when it is fresh.
func (m *Matcher) Advisory(ctx context.Context, id string, ref osv.VulnRef) (*v1alpha1.Vulnerability, error) {
	if v, ok := m.Cache.Get(id); ok && v.ID == id && !v.Modified.Before(ref.Modified) {
		return v, nil
	}
	o, err := m.OSV.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	v := FromOSV(o)
	if err := m.Cache.Put(v); err != nil {
		m.Log.Warn("[vulndb] Cache advisory failed", "id", id, "err", err)
	}
	return v, nil
}

func (m *Matcher) matchProcesses(ctx context.Context, inv *inventory.Inventory) (map[string][]*v1alpha1.Vulnerability, []string) {
	out := map[string][]*v1alpha1.Vulnerability{}
	var warnings []string
	for _, c := range inv.Components {
		if c.Ecosystem != inventory.Process || c.Version == "" {
			continue
		}
		for _, vp := range c.CPEs {
			cves, err := m.NVD.CVEsByCPE(ctx, nvd.CPEName(vp, c.Version))
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("NVD %s %s: %v", vp, c.Version, err))
				continue
			}
			for i := range cves {
				v := FromNVD(&cves[i])
				if err := m.Cache.Put(v); err != nil {
					m.Log.Warn("[vulndb] Cache advisory failed", "id", v.ID, "err", err)
				}
				out[c.ID] = append(out[c.ID], v)
			}
		}
	}
	return out, warnings
}

// dedupe collapses advisories describing the same issue (GHSA and GO ids
// sharing a CVE alias), keeping the record with the most information.
func dedupe(vulns []*v1alpha1.Vulnerability) []*v1alpha1.Vulnerability {
	best := map[string]*v1alpha1.Vulnerability{}
	var order []string
	for _, v := range vulns {
		key := v.DisplayID()
		cur, ok := best[key]
		if !ok {
			order = append(order, key)
			best[key] = v
			continue
		}
		if better(v, cur) {
			best[key] = v
		}
	}
	out := make([]*v1alpha1.Vulnerability, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

func better(a, b *v1alpha1.Vulnerability) bool {
	score := func(v *v1alpha1.Vulnerability) int {
		s := 0
		if v.CVSS != nil && v.CVSS.Score > 0 {
			s += 4
		}
		if strings.HasPrefix(v.ID, "GHSA-") {
			s += 2
		}
		if v.Severity != v1alpha1.SeverityUnknown {
			s++
		}
		return s
	}
	return score(a) > score(b)
}

// Enrich sets KEV and EPSS data on the given advisories in place.
func (m *Matcher) Enrich(ctx context.Context, vulns map[string]*v1alpha1.Vulnerability) error {
	var cves []string
	for _, v := range vulns {
		if v.CVE == "" {
			continue
		}
		cves = append(cves, v.CVE)
		if k, ok := m.KEV.Lookup(v.CVE); ok {
			v.KEV = k
		}
	}
	scores, err := m.EPSS.Scores(ctx, cves)
	for _, v := range vulns {
		if e, ok := scores[v.CVE]; ok {
			v.EPSS = e
		}
	}
	return err
}

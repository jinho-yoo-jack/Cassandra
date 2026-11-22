// Package graph renders a report as the node/edge graph shown in the UI.
package graph

import (
	"slices"
	"strings"

	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
	"github.com/jinho-yoo-jack/vulngraph/pkg/report"
)

// RepositoryNodeID is the ID of the root node.
const RepositoryNodeID = "repository"

// Build returns the graph of a scan report.
func Build(name string, r *report.Report) *v1alpha1.ScanGraph {
	g := &v1alpha1.ScanGraph{
		TypeMeta:   v1alpha1.NewTypeMeta(v1alpha1.KindScanGraph),
		ObjectMeta: v1alpha1.ObjectMeta{Name: name},
	}
	b := &builder{g: g, ids: map[string]bool{}, edges: map[string]bool{}}

	b.node(v1alpha1.GraphNode{
		ID: RepositoryNodeID, Kind: v1alpha1.NodeRepository,
		Label: r.Repository.Owner + "/" + r.Repository.Name, Version: shortCommit(r.Repository.Commit),
	})
	for _, p := range r.Inventory.Projects {
		b.node(v1alpha1.GraphNode{ID: p.ID, Kind: v1alpha1.NodeProject, Label: p.Name, Path: p.Manifest, Ecosystem: string(p.Ecosystem)})
		b.edge(RepositoryNodeID, p.ID, v1alpha1.EdgeContains)
	}
	for _, p := range r.Code.Packages {
		b.node(v1alpha1.GraphNode{ID: p.ID, Kind: v1alpha1.NodePackage, Label: p.Dir, Path: p.Dir, Language: p.Language})
		parent := p.Project
		if parent == "" {
			parent = RepositoryNodeID
		}
		b.edge(parent, p.ID, v1alpha1.EdgeContains)
	}

	findings := map[string][]v1alpha1.NodeFinding{}
	for _, f := range r.Match.Findings {
		v := r.Match.Vulnerabilities[f.VulnerabilityID]
		nf := v1alpha1.NodeFinding{
			VulnerabilityID: v.ID, DisplayID: v.DisplayID(), Summary: v.Summary,
			Severity: v.Severity, FixedVersion: f.FixedVersion, KnownExploited: v.KEV != nil,
			Remediation: f.Remediation,
		}
		if v.CVSS != nil {
			nf.Score = v.CVSS.Score
		}
		if v.EPSS != nil {
			nf.EPSS = v.EPSS.Score
		}
		findings[f.ComponentID] = append(findings[f.ComponentID], nf)
	}
	for _, c := range r.Inventory.Components {
		n := v1alpha1.GraphNode{
			ID: c.ID, Kind: kindOf(c), Label: c.Name, Version: c.Version, Ecosystem: string(c.Ecosystem),
			PURL: c.PURL, Direct: c.Direct, Dev: c.Dev, Findings: findings[c.ID],
		}
		if c.Image != nil {
			n.Label = strings.TrimPrefix(c.Image.Repository, "library/")
		}
		slices.SortFunc(n.Findings, func(a, b v1alpha1.NodeFinding) int { return b.Severity.Rank() - a.Severity.Rank() })
		if len(n.Findings) > 0 {
			n.Severity = n.Findings[0].Severity
		}
		b.node(n)
	}
	for _, d := range r.Inventory.Dependencies {
		kind := v1alpha1.EdgeDepends
		if c := r.Inventory.Component(d.To); c != nil && c.Ecosystem == inventory.Process {
			kind = v1alpha1.EdgeRuns
		}
		b.edge(d.From, d.To, kind)
	}
	for _, e := range r.Code.Edges {
		b.edge(e.From, e.To, v1alpha1.EdgeImports)
	}
	markVulnerablePaths(g)
	return g
}

func kindOf(c *inventory.Component) v1alpha1.NodeKind {
	switch c.Type {
	case inventory.TypeContainer:
		return v1alpha1.NodeImage
	case inventory.TypeApplication:
		return v1alpha1.NodeProcess
	}
	return v1alpha1.NodeLibrary
}

type builder struct {
	g     *v1alpha1.ScanGraph
	ids   map[string]bool
	edges map[string]bool
}

func (b *builder) node(n v1alpha1.GraphNode) {
	if b.ids[n.ID] {
		return
	}
	b.ids[n.ID] = true
	b.g.Nodes = append(b.g.Nodes, n)
}

func (b *builder) edge(from, to string, kind v1alpha1.EdgeKind) {
	id := from + "->" + to
	if b.edges[id] || from == to {
		return
	}
	b.edges[id] = true
	b.g.Edges = append(b.g.Edges, v1alpha1.GraphEdge{ID: id, Source: from, Target: to, Kind: kind})
}

// markVulnerablePaths flags every node and edge from which a vulnerable node
// is reachable, by walking edges backwards from the vulnerable nodes.
func markVulnerablePaths(g *v1alpha1.ScanGraph) {
	incoming := map[string][]int{}
	for i, e := range g.Edges {
		incoming[e.Target] = append(incoming[e.Target], i)
	}
	index := map[string]int{}
	var queue []string
	for i, n := range g.Nodes {
		index[n.ID] = i
		if len(n.Findings) > 0 {
			g.Nodes[i].OnVulnerablePath = true
			queue = append(queue, n.ID)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, ei := range incoming[cur] {
			g.Edges[ei].OnVulnerablePath = true
			src := g.Edges[ei].Source
			if i, ok := index[src]; ok && !g.Nodes[i].OnVulnerablePath {
				g.Nodes[i].OnVulnerablePath = true
				queue = append(queue, src)
			}
		}
	}
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// Package inventory models what a repository is made of: projects (one per
// manifest), components (libraries, container images, processes) and the
// dependency edges between them. It is the in-memory form of an SBOM.
package inventory

import (
	"slices"
	"sort"
)

// Ecosystem is an OSV ecosystem name, plus Image and Process for container
// images and the server processes they run.
type Ecosystem string

const (
	Go        Ecosystem = "Go"
	NPM       Ecosystem = "npm"
	PyPI      Ecosystem = "PyPI"
	Maven     Ecosystem = "Maven"
	CratesIO  Ecosystem = "crates.io"
	RubyGems  Ecosystem = "RubyGems"
	Packagist Ecosystem = "Packagist"
	Image     Ecosystem = "Image"
	Process   Ecosystem = "Process"
)

// ComponentType mirrors CycloneDX component types.
type ComponentType string

const (
	TypeLibrary     ComponentType = "library"
	TypeContainer   ComponentType = "container"
	TypeApplication ComponentType = "application"
)

// Component is one resolved package, image or process.
type Component struct {
	// ID is the package URL, unique per name and version.
	ID        string        `json:"id"`
	Type      ComponentType `json:"type"`
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	Ecosystem Ecosystem     `json:"ecosystem"`
	PURL      string        `json:"purl"`
	// CPEs are CPE 2.3 vendor:product prefixes (without version) used to
	// match processes against NVD.
	CPEs []string `json:"cpes,omitempty"`
	// Direct is true when any project declares the component itself.
	Direct bool `json:"direct,omitempty"`
	// Dev is true when every occurrence is a development dependency.
	Dev bool `json:"dev,omitempty"`
	// Locations are the manifests the component was found in.
	Locations []string `json:"locations,omitempty"`
	// Image is set for container components.
	Image *ImageRef `json:"image,omitempty"`
}

// ImageRef is a parsed container image reference.
type ImageRef struct {
	Registry   string `json:"registry,omitempty"`
	Repository string `json:"repository"`
	Tag        string `json:"tag,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

// Project is one manifest: a Go module, an npm package, a Dockerfile...
type Project struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Dir       string    `json:"dir"`
	Manifest  string    `json:"manifest"`
	Ecosystem Ecosystem `json:"ecosystem"`
	// Lockfile is the file versions were resolved from, if any.
	Lockfile string `json:"lockfile,omitempty"`
}

// Dependency is a directed edge. From is a project or component ID, To a
// component ID.
type Dependency struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Inventory is the merged result of every extractor.
type Inventory struct {
	Projects     []*Project   `json:"projects"`
	Components   []*Component `json:"components"`
	Dependencies []Dependency `json:"dependencies"`

	index map[string]*Component
	edges map[Dependency]struct{}
}

// Result is what one extractor returns for one manifest.
type Result struct {
	Project      *Project
	Components   []*Component
	Dependencies []Dependency
	// Warnings retain unresolved declarations without discarding valid data.
	// The scan adapter carries these diagnostics into its completeness policy.
	Warnings []string
}

// Component returns the component with the given ID, or nil.
func (inv *Inventory) Component(id string) *Component {
	inv.buildIndex()
	return inv.index[id]
}

func (inv *Inventory) buildIndex() {
	if inv.index != nil {
		return
	}
	inv.index = make(map[string]*Component, len(inv.Components))
	for _, c := range inv.Components {
		inv.index[c.ID] = c
	}
	inv.edges = make(map[Dependency]struct{}, len(inv.Dependencies))
	for _, d := range inv.Dependencies {
		inv.edges[d] = struct{}{}
	}
}

// Merge adds an extractor result, de-duplicating components by ID.
func (inv *Inventory) Merge(r *Result) {
	inv.buildIndex()
	inv.Projects = append(inv.Projects, r.Project)
	for _, c := range r.Components {
		if cur, ok := inv.index[c.ID]; ok {
			cur.Direct = cur.Direct || c.Direct
			cur.Dev = cur.Dev && c.Dev
			for _, l := range c.Locations {
				if !slices.Contains(cur.Locations, l) {
					cur.Locations = append(cur.Locations, l)
				}
			}
			continue
		}
		inv.index[c.ID] = c
		inv.Components = append(inv.Components, c)
	}
	for _, d := range r.Dependencies {
		if d.From == d.To {
			continue
		}
		if _, ok := inv.edges[d]; ok {
			continue
		}
		inv.edges[d] = struct{}{}
		inv.Dependencies = append(inv.Dependencies, d)
	}
}

// Sort orders everything deterministically so SBOM output is reproducible.
func (inv *Inventory) Sort() {
	sort.Slice(inv.Projects, func(i, j int) bool { return inv.Projects[i].ID < inv.Projects[j].ID })
	sort.Slice(inv.Components, func(i, j int) bool { return inv.Components[i].ID < inv.Components[j].ID })
	sort.Slice(inv.Dependencies, func(i, j int) bool {
		a, b := inv.Dependencies[i], inv.Dependencies[j]
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
}

// ProjectsOf returns the projects whose manifests contain the component.
func (inv *Inventory) ProjectsOf(c *Component) []*Project {
	var out []*Project
	for _, p := range inv.Projects {
		if slices.Contains(c.Locations, p.Manifest) || (p.Lockfile != "" && slices.Contains(c.Locations, p.Lockfile)) {
			out = append(out, p)
		}
	}
	return out
}

// PathTo returns the shortest chain of IDs from a project to the component,
// e.g. [project:web, express, body-parser], used to explain how a
// transitive dependency is pulled in.
func (inv *Inventory) PathTo(componentID string) []string {
	parents := map[string][]string{}
	for _, d := range inv.Dependencies {
		parents[d.To] = append(parents[d.To], d.From)
	}
	isProject := map[string]bool{}
	for _, p := range inv.Projects {
		isProject[p.ID] = true
	}
	// BFS upwards from the component to the nearest project.
	prev := map[string]string{componentID: ""}
	queue := []string{componentID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if isProject[cur] {
			var path []string
			for n := cur; n != ""; n = prev[n] {
				path = append(path, n)
			}
			return path
		}
		for _, p := range parents[cur] {
			if _, seen := prev[p]; !seen {
				prev[p] = cur
				queue = append(queue, p)
			}
		}
	}
	return []string{componentID}
}

// ProjectID returns the canonical project ID for a manifest path.
func ProjectID(manifest string) string { return "project:" + manifest }

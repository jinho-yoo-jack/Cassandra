// Package codegraph builds the first-party side of the graph: source
// packages (directories) and the imports between them and third-party
// components. Go is parsed with go/parser; JavaScript/TypeScript and Python
// imports are recognised with regular expressions, which is enough to tell
// which directory pulls in which library.
package codegraph

import (
	"context"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

// Package is a directory of first-party source files.
type Package struct {
	ID       string `json:"id"`
	Dir      string `json:"dir"`
	Language string `json:"language"`
	Files    int    `json:"files"`
	// Project is the ID of the inventory project owning the directory.
	Project string `json:"project,omitempty"`
}

// Edge points from a package to another package or to a component.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Graph is the first-party code graph.
type Graph struct {
	Packages []*Package `json:"packages"`
	Edges    []Edge     `json:"edges"`
}

// Options bounds the work done on very large repositories.
type Options struct {
	MaxFiles    int
	MaxPackages int
}

// DefaultOptions are used by the scanner.
var DefaultOptions = Options{MaxFiles: 20000, MaxPackages: 250}

// language analyses source files of one language.
type language interface {
	name() string
	ecosystem() inventory.Ecosystem
	matches(file string) bool
	// imports returns raw import specifiers of a file.
	imports(file string, src []byte) []string
	// resolve maps an import of a file in pkgDir to a package directory
	// (internal) or a component ID (external). ok is false when the import
	// is neither, e.g. a builtin module.
	resolve(r *resolver, proj *inventory.Project, pkgDir, spec string) (target string, internal, ok bool)
}

var languages = []language{goLang{}, jsLang{}, pyLang{}}

// PackageID returns the node ID of a source directory.
func PackageID(dir string) string { return "package:" + dir }

type fileImports struct {
	lang    language
	dir     string
	imports []string
}

// Build walks fsys and returns the code graph of every language.
func Build(ctx context.Context, fsys fs.FS, inv *inventory.Inventory, opts Options) (*Graph, error) {
	var files []fileImports
	pkgs := map[string]*Package{} // dir -> package
	count := 0
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if p != "." && (inventory.SkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if count >= opts.MaxFiles {
			return fs.SkipAll
		}
		for _, l := range languages {
			if !l.matches(p) {
				continue
			}
			src, err := fs.ReadFile(fsys, p)
			if err != nil || len(src) > 2<<20 {
				break
			}
			count++
			dir := path.Dir(p)
			if pkg, ok := pkgs[dir]; ok {
				pkg.Files++
			} else {
				pkgs[dir] = &Package{ID: PackageID(dir), Dir: dir, Language: l.name(), Files: 1}
			}
			files = append(files, fileImports{lang: l, dir: dir, imports: l.imports(p, src)})
			break
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	r := newResolver(inv, pkgs)
	for _, pkg := range pkgs {
		if proj := r.owner(pkg.Dir, languageByName(pkg.Language).ecosystem()); proj != nil {
			pkg.Project = proj.ID
		}
	}

	edgeSet := map[Edge]struct{}{}
	for _, f := range files {
		proj := r.owner(f.dir, f.lang.ecosystem())
		for _, spec := range f.imports {
			target, internal, ok := f.lang.resolve(r, proj, f.dir, spec)
			if !ok {
				continue
			}
			to := target
			if internal {
				dir := r.nearestPackage(target)
				if dir == "" || dir == f.dir {
					continue
				}
				to = PackageID(dir)
			}
			edgeSet[Edge{From: PackageID(f.dir), To: to}] = struct{}{}
		}
	}

	g := &Graph{}
	for _, p := range pkgs {
		g.Packages = append(g.Packages, p)
	}
	for e := range edgeSet {
		g.Edges = append(g.Edges, e)
	}
	collapse(g, opts.MaxPackages)
	sort.Slice(g.Packages, func(i, j int) bool { return g.Packages[i].ID < g.Packages[j].ID })
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})
	return g, nil
}

func languageByName(n string) language {
	for _, l := range languages {
		if l.name() == n {
			return l
		}
	}
	return languages[0]
}

// resolver holds lookup tables shared by the language resolvers.
type resolver struct {
	inv      *inventory.Inventory
	pkgs     map[string]*Package
	projects []*inventory.Project
	// byName maps ecosystem/name to component IDs, preferring direct
	// dependencies declared by the given manifest.
	byName map[string][]*inventory.Component
}

func newResolver(inv *inventory.Inventory, pkgs map[string]*Package) *resolver {
	r := &resolver{inv: inv, pkgs: pkgs, projects: slices.Clone(inv.Projects), byName: map[string][]*inventory.Component{}}
	for _, c := range inv.Components {
		k := string(c.Ecosystem) + "/" + c.Name
		r.byName[k] = append(r.byName[k], c)
	}
	// Longest directory first so owner() finds the nearest project.
	sort.SliceStable(r.projects, func(i, j int) bool { return len(r.projects[i].Dir) > len(r.projects[j].Dir) })
	return r
}

// owner returns the nearest project of the ecosystem containing dir.
func (r *resolver) owner(dir string, eco inventory.Ecosystem) *inventory.Project {
	for _, p := range r.projects {
		if p.Ecosystem == eco && within(dir, p.Dir) {
			return p
		}
	}
	return nil
}

func within(dir, root string) bool {
	return root == "." || dir == root || strings.HasPrefix(dir, root+"/")
}

// component returns the component ID for an ecosystem/name, preferring one
// declared by the project's manifest.
func (r *resolver) component(eco inventory.Ecosystem, name string, proj *inventory.Project) (string, bool) {
	cs := r.byName[string(eco)+"/"+name]
	if len(cs) == 0 {
		return "", false
	}
	if proj != nil {
		for _, c := range cs {
			for _, l := range c.Locations {
				if l == proj.Manifest {
					return c.ID, true
				}
			}
		}
	}
	return cs[0].ID, true
}

// nearestPackage returns the deepest existing package directory at or above
// dir.
func (r *resolver) nearestPackage(dir string) string {
	for d := dir; ; d = path.Dir(d) {
		if _, ok := r.pkgs[d]; ok {
			return d
		}
		if d == "." || d == "/" || d == "" {
			return ""
		}
	}
}

// collapse merges directories into their ancestors until at most
// maxPackages remain, so huge monorepos still render.
func collapse(g *Graph, maxPackages int) {
	if maxPackages <= 0 || len(g.Packages) <= maxPackages {
		return
	}
	maxDepth := 0
	for _, p := range g.Packages {
		maxDepth = max(maxDepth, depth(p.Dir))
	}
	for limit := maxDepth - 1; limit >= 0; limit-- {
		if countAtDepth(g.Packages, limit) <= maxPackages {
			mergeToDepth(g, limit)
			return
		}
	}
	mergeToDepth(g, 0)
}

func depth(dir string) int {
	if dir == "." {
		return 0
	}
	return strings.Count(dir, "/") + 1
}

func truncate(dir string, limit int) string {
	if depth(dir) <= limit {
		return dir
	}
	if limit == 0 {
		return "."
	}
	return strings.Join(strings.Split(dir, "/")[:limit], "/")
}

func countAtDepth(pkgs []*Package, limit int) int {
	seen := map[string]bool{}
	for _, p := range pkgs {
		seen[truncate(p.Dir, limit)] = true
	}
	return len(seen)
}

func mergeToDepth(g *Graph, limit int) {
	merged := map[string]*Package{}
	rename := map[string]string{}
	for _, p := range g.Packages {
		dir := truncate(p.Dir, limit)
		rename[p.ID] = PackageID(dir)
		if m, ok := merged[dir]; ok {
			m.Files += p.Files
			continue
		}
		merged[dir] = &Package{ID: PackageID(dir), Dir: dir, Language: p.Language, Files: p.Files, Project: p.Project}
	}
	g.Packages = g.Packages[:0]
	for _, p := range merged {
		g.Packages = append(g.Packages, p)
	}
	edges := map[Edge]struct{}{}
	for _, e := range g.Edges {
		from := rename[e.From]
		to := e.To
		if n, ok := rename[e.To]; ok {
			to = n
		}
		if from != to {
			edges[Edge{From: from, To: to}] = struct{}{}
		}
	}
	g.Edges = g.Edges[:0]
	for e := range edges {
		g.Edges = append(g.Edges, e)
	}
}

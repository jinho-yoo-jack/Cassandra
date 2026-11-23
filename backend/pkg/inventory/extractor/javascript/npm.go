// Package javascript extracts npm packages from package.json and the
// lockfile next to it (package-lock.json, pnpm-lock.yaml or yarn.lock).
package javascript

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

// Extractor handles package.json. The lockfile, when present, supplies the
// resolved versions and the transitive graph.
type Extractor struct{}

func (Extractor) Name() string { return "javascript/npm" }

func (Extractor) FileRequired(p string) bool { return path.Base(p) == "package.json" }

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// lockParser parses one lockfile format into a Result.
type lockParser func(data []byte, pkg *packageJSON, b *builder) error

func (Extractor) Extract(ctx context.Context, in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}
	name := pkg.Name
	if name == "" {
		name = in.Dir()
	}
	proj := &inventory.Project{
		ID: inventory.ProjectID(in.Path), Name: name, Dir: in.Dir(),
		Manifest: in.Path, Ecosystem: inventory.NPM,
	}

	locks := []struct {
		file  string
		parse lockParser
	}{
		{"package-lock.json", parsePackageLock},
		{"npm-shrinkwrap.json", parsePackageLock},
		{"pnpm-lock.yaml", parsePnpmLock},
		{"yarn.lock", parseYarnLock},
	}
	for _, l := range locks {
		lp := in.Sibling(l.file)
		if !in.Exists(lp) {
			continue
		}
		lockData, err := in.ReadFile(lp)
		if err != nil {
			return nil, err
		}
		b := newBuilder(proj, in.Path)
		if err := l.parse(lockData, &pkg, b); err != nil {
			return nil, err
		}
		proj.Lockfile = lp
		b.checkDeclared(&pkg)
		return b.result(), nil
	}

	// A workspace member without its own lockfile is resolved by the
	// workspace root; reporting it again from ranges would only add noise.
	for dir := path.Dir(in.Dir()); dir != "." && dir != "/"; dir = path.Dir(dir) {
		for _, l := range locks {
			if lp := path.Join(dir, l.file); in.Exists(lp) {
				return checkAncestorLock(in, lp, l.parse, &pkg, proj)
			}
		}
	}
	for _, l := range locks {
		if in.Dir() != "." && in.Exists(l.file) {
			return checkAncestorLock(in, l.file, l.parse, &pkg, proj)
		}
	}

	// No lockfile: fall back to the lowest version allowed by each range.
	b := newBuilder(proj, in.Path)
	addRanges := func(deps map[string]string, dev bool) {
		for n, r := range deps {
			if localDependency(r) {
				continue
			}
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("dependency %s has no lockfile-resolved version; declared range fallback is incomplete", n))
			if v := inventory.VersionFromRange(r); v != "" {
				b.addDirect(n, v, dev)
			}
		}
	}
	addRanges(pkg.Dependencies, false)
	addRanges(pkg.OptionalDependencies, false)
	addRanges(pkg.DevDependencies, true)
	return b.result(), nil
}

// checkAncestorLock verifies a workspace member before suppressing duplicates.
func checkAncestorLock(in *inventory.Input, lp string, parse lockParser, pkg *packageJSON, proj *inventory.Project) (*inventory.Result, error) {
	data, err := in.ReadFile(lp)
	if err != nil {
		return nil, err
	}
	b := newBuilder(proj, in.Path)
	if err := parse(data, pkg, b); err != nil {
		return nil, fmt.Errorf("%s: %w", lp, err)
	}
	b.checkDeclared(pkg)
	if len(b.res.Warnings) == 0 {
		return nil, nil
	}
	return &inventory.Result{Project: proj, Warnings: b.res.Warnings}, nil
}

// builder accumulates components and edges for one project.
type builder struct {
	proj     *inventory.Project
	location string
	comps    map[string]*inventory.Component
	res      *inventory.Result
}

func newBuilder(proj *inventory.Project, location string) *builder {
	return &builder{
		proj: proj, location: location,
		comps: map[string]*inventory.Component{},
		res:   &inventory.Result{Project: proj},
	}
}

func (b *builder) component(name, version string, dev bool) *inventory.Component {
	version = cleanVersion(version)
	c := inventory.NewLibrary(inventory.NPM, name, version, b.location, false, dev)
	if cur, ok := b.comps[c.ID]; ok {
		cur.Dev = cur.Dev && dev
		return cur
	}
	b.comps[c.ID] = c
	b.res.Components = append(b.res.Components, c)
	return c
}

func (b *builder) addDirect(name, version string, dev bool) *inventory.Component {
	c := b.component(name, version, dev)
	c.Direct = true
	b.edge(b.proj.ID, c.ID)
	return c
}

func (b *builder) edge(from, to string) {
	if from == "" || to == "" {
		return
	}
	b.res.Dependencies = append(b.res.Dependencies, inventory.Dependency{From: from, To: to})
}

func (b *builder) result() *inventory.Result { return b.res }

func localDependency(spec string) bool {
	return strings.HasPrefix(spec, "workspace:") || strings.HasPrefix(spec, "file:") || strings.HasPrefix(spec, "link:")
}

func (b *builder) checkDeclared(pkg *packageJSON) {
	for name, spec := range merge(pkg.Dependencies, pkg.OptionalDependencies, pkg.DevDependencies) {
		if localDependency(spec) {
			continue
		}
		found := false
		for _, c := range b.res.Components {
			if c.Name == name && c.Version != "" {
				found = true
				break
			}
		}
		if !found {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("declared dependency %s is not resolved by the lockfile", name))
		}
	}
}

// cleanVersion strips pnpm peer suffixes such as "1.0.0(react@19.0.0)".
func cleanVersion(v string) string {
	if i := strings.IndexByte(v, '('); i > 0 {
		v = v[:i]
	}
	return strings.TrimPrefix(v, "v")
}

func isDirect(pkg *packageJSON, name string) (direct, dev bool) {
	if _, ok := pkg.Dependencies[name]; ok {
		return true, false
	}
	if _, ok := pkg.OptionalDependencies[name]; ok {
		return true, false
	}
	if _, ok := pkg.DevDependencies[name]; ok {
		return true, true
	}
	return false, false
}

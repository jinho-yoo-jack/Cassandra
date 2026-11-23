// Package python extracts PyPI packages from requirements files,
// pyproject.toml (with uv.lock or poetry.lock) and Pipfile.lock.
package python

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

// Extractor handles every Python manifest format.
type Extractor struct{}

func (Extractor) Name() string { return "python" }

var requirementsFile = regexp.MustCompile(`(^|/)(requirements[^/]*\.txt|requirements/[^/]+\.txt)$`)

func (Extractor) FileRequired(p string) bool {
	switch path.Base(p) {
	case "pyproject.toml", "Pipfile", "Pipfile.lock":
		return true
	}
	return requirementsFile.MatchString(p)
}

func (e Extractor) Extract(ctx context.Context, in *inventory.Input) (*inventory.Result, error) {
	switch path.Base(in.Path) {
	case "pyproject.toml":
		return e.pyproject(in)
	case "Pipfile.lock":
		return e.pipfileLock(in)
	case "Pipfile":
		return e.pipfile(in)
	default:
		return e.requirements(in)
	}
}

func newProject(in *inventory.Input, name string) *inventory.Project {
	return &inventory.Project{
		ID: inventory.ProjectID(in.Path), Name: name, Dir: in.Dir(),
		Manifest: in.Path, Ecosystem: inventory.PyPI,
	}
}

type builder struct {
	res   *inventory.Result
	loc   string
	comps map[string]*inventory.Component // normalised name -> component
}

func newBuilder(p *inventory.Project) *builder {
	return &builder{res: &inventory.Result{Project: p}, loc: p.Manifest, comps: map[string]*inventory.Component{}}
}

func (b *builder) add(name, version string, direct, dev bool) *inventory.Component {
	key := inventory.NormalizePyPI(name)
	if c, ok := b.comps[key]; ok {
		return c
	}
	c := inventory.NewLibrary(inventory.PyPI, key, version, b.loc, direct, dev)
	b.comps[key] = c
	b.res.Components = append(b.res.Components, c)
	if direct {
		b.res.Dependencies = append(b.res.Dependencies, inventory.Dependency{From: b.res.Project.ID, To: c.ID})
	}
	return c
}

func (b *builder) edge(from, to string) {
	f, ok1 := b.comps[inventory.NormalizePyPI(from)]
	t, ok2 := b.comps[inventory.NormalizePyPI(to)]
	if ok1 && ok2 {
		b.res.Dependencies = append(b.res.Dependencies, inventory.Dependency{From: f.ID, To: t.ID})
	}
}

// requirementLine matches "name[extras] <op> version".
var requirementLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(===|==|~=|>=|>)?\s*([^\s;,#]*)`)

func (Extractor) requirements(in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	b := newBuilder(newProject(in, in.Path))
	dev := strings.Contains(path.Base(in.Path), "dev") || strings.Contains(path.Base(in.Path), "test")
	sc := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") || strings.Contains(line, "://") {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("line %d: unsupported requirement directive, include or URL; dependency resolution incomplete", lineNo))
			continue
		}
		m := requirementLine.FindStringSubmatch(line)
		if m == nil {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("line %d: malformed requirement", lineNo))
			continue
		}
		if m[3] == "" || m[4] == "" || strings.ContainsAny(m[4], "*<>=!~@") {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("line %d: dependency %s has no resolved version", lineNo, m[1]))
			continue
		}
		if m[3] != "==" && m[3] != "===" {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("line %d: dependency %s is a range, not a resolved version; using declared lower bound", lineNo, m[1]))
		}
		b.add(m[1], m[4], true, dev)
	}
	return b.res, sc.Err()
}

type pyprojectFile struct {
	Project struct {
		Name                 string              `toml:"name"`
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		Poetry struct {
			Name            string                    `toml:"name"`
			Dependencies    map[string]any            `toml:"dependencies"`
			DevDependencies map[string]any            `toml:"dev-dependencies"`
			Group           map[string]map[string]any `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// declared returns normalised direct dependency names mapped to "is dev".
func (p *pyprojectFile) declared(b *builder) map[string]bool {
	out := map[string]bool{}
	add := func(spec string, dev bool) {
		if m := requirementLine.FindStringSubmatch(spec); m != nil {
			n := inventory.NormalizePyPI(m[1])
			if cur, ok := out[n]; !ok || cur {
				out[n] = dev
			}
		} else {
			b.res.Warnings = append(b.res.Warnings, "malformed dependency declaration in pyproject.toml")
		}
	}
	for _, d := range p.Project.Dependencies {
		add(d, false)
	}
	for _, ds := range p.Project.OptionalDependencies {
		for _, d := range ds {
			add(d, false)
		}
	}
	for _, ds := range p.DependencyGroups {
		for _, d := range ds {
			if s, ok := d.(string); ok {
				add(s, true)
			} else {
				b.res.Warnings = append(b.res.Warnings, "unsupported dependency group include; resolution incomplete")
			}
		}
	}
	for n := range p.Tool.Poetry.Dependencies {
		if n != "python" {
			add(n, false)
		}
	}
	for n := range p.Tool.Poetry.DevDependencies {
		add(n, true)
	}
	for _, g := range p.Tool.Poetry.Group {
		if deps, ok := g["dependencies"].(map[string]any); ok {
			for n := range deps {
				add(n, true)
			}
		}
	}
	return out
}

type lockFile struct {
	Package []struct {
		Name         string         `toml:"name"`
		Version      string         `toml:"version"`
		Category     string         `toml:"category"`
		Source       map[string]any `toml:"source"`
		Dependencies any            `toml:"dependencies"`
	} `toml:"package"`
}

func (Extractor) pyproject(in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	var py pyprojectFile
	if _, err := toml.Decode(string(data), &py); err != nil {
		return nil, err
	}
	name := py.Project.Name
	if name == "" {
		name = py.Tool.Poetry.Name
	}
	if name == "" {
		name = in.Dir()
	}
	proj := newProject(in, name)
	b := newBuilder(proj)
	declared := py.declared(b)

	for _, lockName := range []string{"uv.lock", "poetry.lock"} {
		lp := in.Sibling(lockName)
		if !in.Exists(lp) {
			continue
		}
		lockData, err := in.ReadFile(lp)
		if err != nil {
			return nil, err
		}
		var lock lockFile
		meta, err := toml.Decode(string(lockData), &lock)
		if err != nil {
			return nil, err
		}
		if !meta.IsDefined("package") && !meta.IsDefined("version") && !meta.IsDefined("metadata") {
			return nil, fmt.Errorf("%s: missing lock structure (package/version/metadata)", lockName)
		}
		proj.Lockfile = lp
		resolved := map[string]bool{}
		self := inventory.NormalizePyPI(name)
		for _, p := range lock.Package {
			n := inventory.NormalizePyPI(p.Name)
			if n == self || isLocalSource(p.Source) {
				resolved[n] = true
				continue
			}
			if p.Name == "" || p.Version == "" {
				b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("%s: package %q has no resolved name/version", lockName, p.Name))
				continue
			}
			resolved[n] = true
			dev, direct := declared[n]
			b.add(p.Name, p.Version, direct, direct && dev || p.Category == "dev")
		}
		for _, p := range lock.Package {
			for _, dep := range lockDependencyNames(p.Dependencies) {
				if inventory.NormalizePyPI(p.Name) == self {
					continue
				}
				b.edge(p.Name, dep)
			}
		}
		for n := range declared {
			if !resolved[n] {
				b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("declared dependency %s is not resolved by %s", n, lockName))
			}
		}
		return b.res, nil
	}
	for n := range declared {
		b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("dependency %s has no lockfile-resolved version", n))
	}

	// No lockfile: use the lower bounds of declared ranges.
	for _, spec := range py.Project.Dependencies {
		if m := requirementLine.FindStringSubmatch(spec); m != nil && m[3] != "" {
			if v := inventory.VersionFromRange(m[4]); v != "" {
				b.add(m[1], v, true, false)
			}
		}
	}
	for n, v := range py.Tool.Poetry.Dependencies {
		if s, ok := v.(string); ok && n != "python" {
			if ver := inventory.VersionFromRange(s); ver != "" {
				b.add(n, ver, true, false)
			}
		}
	}
	return b.res, nil
}

func isLocalSource(src map[string]any) bool {
	for _, k := range []string{"virtual", "editable", "directory", "path"} {
		if _, ok := src[k]; ok {
			return true
		}
	}
	return false
}

// lockDependencyNames reads uv's [{name = "x"}] and poetry's {x = ">=1"}.
func lockDependencyNames(v any) []string {
	var out []string
	switch deps := v.(type) {
	case []map[string]any:
		for _, d := range deps {
			if n, ok := d["name"].(string); ok {
				out = append(out, n)
			}
		}
	case []any:
		for _, d := range deps {
			if m, ok := d.(map[string]any); ok {
				if n, ok := m["name"].(string); ok {
					out = append(out, n)
				}
			}
		}
	case map[string]any:
		for n := range deps {
			out = append(out, n)
		}
	}
	return out
}

func (Extractor) pipfileLock(in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
			Path    string `json:"path"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
			Path    string `json:"path"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	if lock.Default == nil && lock.Develop == nil {
		return nil, fmt.Errorf("Pipfile.lock: missing default/develop dependency maps")
	}
	b := newBuilder(newProject(in, in.Dir()))
	for n, p := range lock.Default {
		if p.Path != "" {
			continue
		}
		if v := strings.TrimPrefix(p.Version, "=="); strings.HasPrefix(p.Version, "==") && v != "" && !strings.ContainsAny(v, "*<>=!~") {
			b.add(n, v, true, false)
		} else {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("Pipfile.lock: dependency %s has no resolved version", n))
		}
	}
	for n, p := range lock.Develop {
		if p.Path != "" {
			continue
		}
		if v := strings.TrimPrefix(p.Version, "=="); strings.HasPrefix(p.Version, "==") && v != "" && !strings.ContainsAny(v, "*<>=!~") {
			b.add(n, v, true, true)
		} else {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("Pipfile.lock: dependency %s has no resolved version", n))
		}
	}
	return b.res, nil
}

func (e Extractor) pipfile(in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Packages    map[string]any `toml:"packages"`
		DevPackages map[string]any `toml:"dev-packages"`
	}
	if _, err := toml.Decode(string(data), &manifest); err != nil {
		return nil, err
	}
	b := newBuilder(newProject(in, in.Dir()))
	resolved := map[string]bool{}
	if lp := in.Sibling("Pipfile.lock"); in.Exists(lp) {
		lock, err := e.pipfileLock(&inventory.Input{FS: in.FS, Path: lp})
		if err != nil {
			return nil, err
		}
		for _, c := range lock.Components {
			resolved[inventory.NormalizePyPI(c.Name)] = true
		}
	}
	for _, deps := range []map[string]any{manifest.Packages, manifest.DevPackages} {
		for n, spec := range deps {
			if src, ok := spec.(map[string]any); ok && isLocalSource(src) {
				continue
			}
			if !resolved[inventory.NormalizePyPI(n)] {
				b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("dependency %s has no Pipfile.lock-resolved version", n))
			}
		}
	}
	return b.res, nil
}

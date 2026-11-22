// Package python extracts PyPI packages from requirements files,
// pyproject.toml (with uv.lock or poetry.lock) and Pipfile.lock.
package python

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
)

// Extractor handles every Python manifest format.
type Extractor struct{}

func (Extractor) Name() string { return "python" }

var requirementsFile = regexp.MustCompile(`(^|/)(requirements[^/]*\.txt|requirements/[^/]+\.txt)$`)

func (Extractor) FileRequired(p string) bool {
	switch path.Base(p) {
	case "pyproject.toml", "Pipfile.lock":
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
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.Contains(line, "://") {
			continue
		}
		m := requirementLine.FindStringSubmatch(line)
		if m == nil || m[4] == "" {
			continue
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
func (p *pyprojectFile) declared() map[string]bool {
	out := map[string]bool{}
	add := func(spec string, dev bool) {
		if m := requirementLine.FindStringSubmatch(spec); m != nil {
			n := inventory.NormalizePyPI(m[1])
			if cur, ok := out[n]; !ok || cur {
				out[n] = dev
			}
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
	declared := py.declared()
	b := newBuilder(proj)

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
		if _, err := toml.Decode(string(lockData), &lock); err != nil {
			return nil, err
		}
		proj.Lockfile = lp
		self := inventory.NormalizePyPI(name)
		for _, p := range lock.Package {
			n := inventory.NormalizePyPI(p.Name)
			if n == self || isLocalSource(p.Source) {
				continue
			}
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
		return b.res, nil
	}

	// No lockfile: use the lower bounds of declared ranges.
	for _, spec := range py.Project.Dependencies {
		if m := requirementLine.FindStringSubmatch(spec); m != nil && m[4] != "" {
			b.add(m[1], inventory.VersionFromRange(m[4]), true, false)
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
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	b := newBuilder(newProject(in, in.Dir()))
	for n, p := range lock.Default {
		if v := strings.TrimLeft(p.Version, "=="); v != "" {
			b.add(n, v, true, false)
		}
	}
	for n, p := range lock.Develop {
		if v := strings.TrimLeft(p.Version, "=="); v != "" {
			b.add(n, v, true, true)
		}
	}
	return b.res, nil
}

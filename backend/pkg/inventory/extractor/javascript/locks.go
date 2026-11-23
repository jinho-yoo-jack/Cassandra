package javascript

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"sigs.k8s.io/yaml"
)

// ---------------------------------------------------------------------------
// package-lock.json / npm-shrinkwrap.json
// ---------------------------------------------------------------------------

type packageLock struct {
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]packageLockEntry `json:"packages"`
	Dependencies    map[string]packageLockV1    `json:"dependencies"`
}

type packageLockEntry struct {
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

type packageLockV1 struct {
	Version      string                   `json:"version"`
	Dev          bool                     `json:"dev"`
	Requires     map[string]string        `json:"requires"`
	Dependencies map[string]packageLockV1 `json:"dependencies"`
}

func parsePackageLock(data []byte, pkg *packageJSON, b *builder) error {
	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return err
	}
	if lock.LockfileVersion < 1 || lock.LockfileVersion > 3 {
		return fmt.Errorf("package lock: missing or unsupported lockfileVersion")
	}
	if lock.LockfileVersion >= 2 && lock.Packages == nil {
		return fmt.Errorf("package lock: missing packages map")
	}
	if len(lock.Packages) > 0 {
		parsePackageLockV2(&lock, b)
		return nil
	}
	parsePackageLockV1(&lock, pkg, b)
	return nil
}

// parsePackageLockV2 handles lockfileVersion 2 and 3, whose "packages" map is
// keyed by install path. Dependencies are resolved with the node_modules
// lookup algorithm: nearest node_modules first, then each ancestor.
func parsePackageLockV2(lock *packageLock, b *builder) {
	idOf := map[string]string{}
	for key, e := range lock.Packages {
		if key != "" && !e.Link && strings.Contains(key, "node_modules/") && e.Version == "" {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("package lock: %s has no resolved version", key))
		}
		if key == "" || e.Link || !strings.Contains(key, "node_modules/") || e.Version == "" {
			continue
		}
		idOf[key] = b.component(installName(key), e.Version, e.Dev).ID
	}

	resolve := func(from, name string) (string, bool) {
		for dir := from; ; dir = parentInstallDir(dir) {
			candidate := "node_modules/" + name
			if dir != "" {
				candidate = dir + "/node_modules/" + name
			}
			if id, ok := idOf[candidate]; ok {
				return id, true
			}
			if dir == "" {
				return "", false
			}
		}
	}

	for key, e := range lock.Packages {
		if e.Link {
			continue
		}
		deps := merge(e.Dependencies, e.OptionalDependencies)
		// The root ("") and workspace members (paths outside node_modules)
		// are first party: their dependencies are direct.
		firstParty := key == "" || !strings.Contains(key, "node_modules/")
		if firstParty {
			for name := range merge(deps, e.DevDependencies) {
				if id, ok := resolve(key, name); ok {
					_, isDev := e.DevDependencies[name]
					c := b.comps[id]
					c.Direct = true
					c.Dev = c.Dev && isDev
					b.edge(b.proj.ID, id)
				}
			}
			continue
		}
		from, ok := idOf[key]
		if !ok {
			continue
		}
		for name, spec := range deps {
			if id, ok := resolve(key, name); ok {
				b.edge(from, id)
			} else if !localDependency(spec) {
				b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("package lock: %s dependency %s is unresolved", key, name))
			}
		}
	}
}

// installName returns the package name of an install path:
// "node_modules/a/node_modules/@s/b" -> "@s/b".
func installName(key string) string {
	i := strings.LastIndex(key, "node_modules/")
	return key[i+len("node_modules/"):]
}

// parentInstallDir strips the last node_modules segment.
func parentInstallDir(key string) string {
	i := strings.LastIndex(key, "node_modules/")
	if i <= 0 {
		return ""
	}
	return key[:i-1]
}

func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// parsePackageLockV1 handles lockfileVersion 1, a nested tree where each
// package may carry its own "dependencies" scope.
func parsePackageLockV1(lock *packageLock, pkg *packageJSON, b *builder) {
	type scope struct {
		parent *scope
		deps   map[string]packageLockV1
		ids    map[string]string
	}
	var walk func(s *scope)
	resolve := func(s *scope, name string) (string, bool) {
		for cur := s; cur != nil; cur = cur.parent {
			if id, ok := cur.ids[name]; ok {
				return id, true
			}
		}
		return "", false
	}
	walk = func(s *scope) {
		for name, d := range s.deps {
			if d.Version == "" {
				b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("package lock: %s has no resolved version", name))
				continue
			}
			s.ids[name] = b.component(name, d.Version, d.Dev).ID
		}
		for name, d := range s.deps {
			child := &scope{parent: s, deps: d.Dependencies, ids: map[string]string{}}
			walk(child)
			for req := range d.Requires {
				if id, ok := resolve(child, req); ok {
					b.edge(s.ids[name], id)
				}
			}
		}
	}
	root := &scope{deps: lock.Dependencies, ids: map[string]string{}}
	walk(root)
	for name, id := range root.ids {
		if direct, dev := isDirect(pkg, name); direct {
			c := b.comps[id]
			c.Direct, c.Dev = true, dev
			b.edge(b.proj.ID, id)
		}
	}
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml (v6 and v9)
// ---------------------------------------------------------------------------

type pnpmLock struct {
	LockfileVersion any                     `json:"lockfileVersion"`
	Importers       map[string]pnpmImporter `json:"importers"`
	// v6 single project layout keeps the importer at the top level.
	pnpmImporter
	Packages  map[string]pnpmPackage `json:"packages"`
	Snapshots map[string]pnpmPackage `json:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmDep `json:"dependencies"`
	DevDependencies      map[string]pnpmDep `json:"devDependencies"`
	OptionalDependencies map[string]pnpmDep `json:"optionalDependencies"`
}

// pnpmDep is {specifier, version} in v6+ and a bare version string before.
type pnpmDep struct {
	Version string
}

func (d *pnpmDep) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &d.Version)
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	d.Version = v.Version
	return nil
}

type pnpmPackage struct {
	Dev                  *bool             `json:"dev"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func parsePnpmLock(data []byte, _ *packageJSON, b *builder) error {
	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return err
	}
	if lock.LockfileVersion == nil {
		return fmt.Errorf("pnpm lock: missing lockfileVersion")
	}
	// v9 keeps the dependency graph in snapshots, v6 in packages.
	graph := lock.Snapshots
	if len(graph) == 0 {
		graph = lock.Packages
	}

	ids := map[string]string{} // name@version -> component ID
	for key, p := range graph {
		name, version, ok := splitPnpmKey(key)
		if !ok || version == "" {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("pnpm lock: invalid or unresolved package key %q", key))
			continue
		}
		dev := p.Dev != nil && *p.Dev
		ids[name+"@"+version] = b.component(name, version, dev).ID
	}
	lookup := func(name, version string) (string, bool) {
		if strings.HasPrefix(version, "link:") || strings.HasPrefix(version, "file:") || strings.HasPrefix(version, "workspace:") {
			return "", false
		}
		id, ok := ids[name+"@"+cleanVersion(version)]
		return id, ok
	}
	for key, p := range graph {
		name, version, ok := splitPnpmKey(key)
		if !ok {
			continue
		}
		from := ids[name+"@"+version]
		for dn, dv := range merge(p.Dependencies, p.OptionalDependencies) {
			// v6 may encode an aliased dependency as "/real-name@1.0.0".
			if strings.HasPrefix(dv, "/") {
				if n, v, ok := splitPnpmKey(dv); ok {
					dn, dv = n, v
				}
			}
			if id, ok := lookup(dn, dv); ok {
				b.edge(from, id)
			} else if !localDependency(dv) {
				b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("pnpm lock: %s dependency %s is unresolved", key, dn))
			}
		}
	}

	importers := lock.Importers
	if len(importers) == 0 {
		importers = map[string]pnpmImporter{".": lock.pnpmImporter}
	}
	for _, imp := range importers {
		addImporterDeps := func(deps map[string]pnpmDep, dev bool) {
			for n, d := range deps {
				if id, ok := lookup(n, d.Version); ok {
					c := b.comps[id]
					c.Direct = true
					c.Dev = c.Dev && dev
					b.edge(b.proj.ID, id)
				}
			}
		}
		addImporterDeps(imp.Dependencies, false)
		addImporterDeps(imp.OptionalDependencies, false)
		addImporterDeps(imp.DevDependencies, true)
	}
	return nil
}

// splitPnpmKey parses "/@scope/name@1.0.0(peer@1)" (v6) or
// "@scope/name@1.0.0(peer@1)" (v9) into name and version.
func splitPnpmKey(key string) (name, version string, ok bool) {
	key = strings.TrimPrefix(key, "/")
	if i := strings.IndexByte(key, '('); i > 0 {
		key = key[:i]
	}
	at := strings.LastIndexByte(key, '@')
	if at <= 0 {
		return "", "", false
	}
	return key[:at], key[at+1:], true
}

// ---------------------------------------------------------------------------
// yarn.lock (classic v1 and berry)
// ---------------------------------------------------------------------------

type yarnEntry struct {
	version string
	deps    map[string]string
}

func parseYarnLock(data []byte, pkg *packageJSON, b *builder) error {
	entries, descriptors, err := parseYarnEntries(data)
	if err != nil {
		return err
	}
	lookup := func(name, rng string) (*yarnEntry, bool) {
		for _, d := range []string{name + "@" + rng, name + "@npm:" + rng} {
			if e, ok := descriptors[d]; ok {
				return e, true
			}
		}
		return nil, false
	}
	ids := map[*yarnEntry]string{}
	for _, e := range entries {
		if e.name == "" || e.entry.version == "" {
			b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("yarn lock: package %q has no resolved version", e.name))
			continue
		}
		ids[e.entry] = b.component(e.name, e.entry.version, false).ID
	}
	for _, e := range entries {
		for dn, dr := range e.entry.deps {
			if t, ok := lookup(dn, dr); ok && ids[t] != "" {
				b.edge(ids[e.entry], ids[t])
			} else if !localDependency(dr) {
				b.res.Warnings = append(b.res.Warnings, fmt.Sprintf("yarn lock: %s dependency %s is unresolved", e.name, dn))
			}
		}
	}
	addRoot := func(deps map[string]string, dev bool) {
		for n, r := range deps {
			if t, ok := lookup(n, r); ok && ids[t] != "" {
				c := b.comps[ids[t]]
				c.Direct = true
				c.Dev = c.Dev && dev
				b.edge(b.proj.ID, c.ID)
			}
		}
	}
	// yarn.lock does not record dev-ness, so only direct dev dependencies
	// are marked.
	addRoot(pkg.Dependencies, false)
	addRoot(pkg.OptionalDependencies, false)
	addRoot(pkg.DevDependencies, true)
	return nil
}

type namedYarnEntry struct {
	name  string
	entry *yarnEntry
}

// parseYarnEntries is a line based parser for both yarn formats. Headers are
// unindented and list descriptors; fields are indented two spaces; entries
// of dependency blocks four spaces.
func parseYarnEntries(data []byte) ([]namedYarnEntry, map[string]*yarnEntry, error) {
	var (
		entries     []namedYarnEntry
		descriptors = map[string]*yarnEntry{}
		cur         *yarnEntry
		inDeps      bool
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0:
			inDeps = false
			if !strings.HasSuffix(trimmed, ":") {
				return nil, nil, fmt.Errorf("yarn lock: malformed entry header")
			}
			header := strings.TrimSuffix(trimmed, ":")
			if header == "__metadata" {
				cur = nil
				continue
			}
			cur = &yarnEntry{deps: map[string]string{}}
			var name string
			for d := range strings.SplitSeq(header, ",") {
				d = unquote(strings.TrimSpace(d))
				descriptors[d] = cur
				if name == "" {
					name = descriptorName(d)
				}
			}
			entries = append(entries, namedYarnEntry{name: name, entry: cur})
		case cur == nil:
			continue
		case indent == 2:
			key, val := splitYarnField(trimmed)
			inDeps = key == "dependencies" || key == "optionalDependencies"
			if key == "version" {
				cur.version = val
			}
		case indent >= 4 && inDeps:
			key, val := splitYarnField(trimmed)
			cur.deps[key] = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("yarn.lock: %w", err)
	}
	return entries, descriptors, nil
}

// splitYarnField splits `key "value"` (v1) and `key: value` (berry).
func splitYarnField(s string) (string, string) {
	var key, val string
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`) + 1
		key, val = s[1:end], s[end+1:]
	} else if i := strings.IndexAny(s, " :"); i >= 0 {
		key, val = s[:i], s[i+1:]
	} else {
		return s, ""
	}
	val = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(val), ":"))
	return key, unquote(val)
}

// descriptorName returns the package name of "@s/n@npm:^1" or "n@^1".
func descriptorName(d string) string {
	if len(d) < 2 {
		return ""
	}
	at := strings.IndexByte(d[1:], '@')
	if at < 0 {
		return d
	}
	return d[:at+1]
}

func unquote(s string) string { return strings.Trim(s, `"'`) }

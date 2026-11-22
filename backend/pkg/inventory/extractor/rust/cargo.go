// Package rust extracts crates from Cargo.lock.
package rust

import (
	"context"
	"path"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

// Extractor handles Cargo.lock, which records the full resolved graph.
type Extractor struct{}

func (Extractor) Name() string { return "rust/cargo" }

func (Extractor) FileRequired(p string) bool { return path.Base(p) == "Cargo.lock" }

type cargoLock struct {
	Package []struct {
		Name         string   `toml:"name"`
		Version      string   `toml:"version"`
		Source       string   `toml:"source"`
		Dependencies []string `toml:"dependencies"`
	} `toml:"package"`
}

func (Extractor) Extract(ctx context.Context, in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	var lock cargoLock
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, err
	}
	manifest := in.Sibling("Cargo.toml")
	if !in.Exists(manifest) {
		manifest = in.Path
	}
	proj := &inventory.Project{
		ID: inventory.ProjectID(manifest), Name: in.Dir(), Dir: in.Dir(),
		Manifest: manifest, Lockfile: in.Path, Ecosystem: inventory.CratesIO,
	}
	res := &inventory.Result{Project: proj}

	// Dependencies are "name" or "name version" when ambiguous.
	byName := map[string][]string{}            // name -> versions
	ids := map[string]string{}                 // name@version -> ID
	comps := map[string]*inventory.Component{} // ID -> component
	local := map[string]bool{}                 // workspace members have no source
	for _, p := range lock.Package {
		if p.Source == "" {
			local[p.Name+"@"+p.Version] = true
			continue
		}
		c := inventory.NewLibrary(inventory.CratesIO, p.Name, p.Version, manifest, false, false)
		ids[p.Name+"@"+p.Version] = c.ID
		comps[c.ID] = c
		byName[p.Name] = append(byName[p.Name], p.Version)
		res.Components = append(res.Components, c)
	}
	resolve := func(dep string) (string, bool) {
		name, version, _ := strings.Cut(dep, " ")
		if version == "" {
			if vs := byName[name]; len(vs) == 1 {
				version = vs[0]
			}
		}
		id, ok := ids[name+"@"+version]
		return id, ok
	}
	for _, p := range lock.Package {
		key := p.Name + "@" + p.Version
		from := ids[key]
		if local[key] {
			from = proj.ID
		}
		for _, d := range p.Dependencies {
			id, ok := resolve(d)
			if !ok {
				continue
			}
			if local[key] {
				comps[id].Direct = true
			}
			res.Dependencies = append(res.Dependencies, inventory.Dependency{From: from, To: id})
		}
	}
	return res, nil
}

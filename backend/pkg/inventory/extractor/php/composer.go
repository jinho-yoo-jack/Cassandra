// Package php extracts Composer packages from composer.lock.
package php

import (
	"context"
	"encoding/json"
	"path"
	"strings"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

// Extractor handles composer.lock.
type Extractor struct{}

func (Extractor) Name() string { return "php/composer" }

func (Extractor) FileRequired(p string) bool { return path.Base(p) == "composer.lock" }

type composerPackage struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
}

func (Extractor) Extract(ctx context.Context, in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	manifest := in.Sibling("composer.json")
	var root composerPackage
	var rootDev map[string]string
	if in.Exists(manifest) {
		if raw, err := in.ReadFile(manifest); err == nil {
			var m struct {
				composerPackage
				RequireDev map[string]string `json:"require-dev"`
			}
			if json.Unmarshal(raw, &m) == nil {
				root, rootDev = m.composerPackage, m.RequireDev
			}
		}
	} else {
		manifest = in.Path
	}
	proj := &inventory.Project{
		ID: inventory.ProjectID(manifest), Name: firstNonEmpty(root.Name, in.Dir()), Dir: in.Dir(),
		Manifest: manifest, Lockfile: in.Path, Ecosystem: inventory.Packagist,
	}
	res := &inventory.Result{Project: proj}

	comps := map[string]*inventory.Component{}
	add := func(pkgs []composerPackage, dev bool) {
		for _, p := range pkgs {
			c := inventory.NewLibrary(inventory.Packagist, p.Name, strings.TrimPrefix(p.Version, "v"), manifest, false, dev)
			comps[p.Name] = c
			res.Components = append(res.Components, c)
		}
	}
	add(lock.Packages, false)
	add(lock.PackagesDev, true)

	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		for dep := range p.Require {
			if t, ok := comps[dep]; ok {
				res.Dependencies = append(res.Dependencies, inventory.Dependency{From: comps[p.Name].ID, To: t.ID})
			}
		}
	}
	for _, reqs := range []map[string]string{root.Require, rootDev} {
		for dep := range reqs {
			if c, ok := comps[dep]; ok {
				c.Direct = true
				res.Dependencies = append(res.Dependencies, inventory.Dependency{From: proj.ID, To: c.ID})
			}
		}
	}
	return res, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

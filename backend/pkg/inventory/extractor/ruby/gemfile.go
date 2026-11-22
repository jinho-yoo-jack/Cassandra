// Package ruby extracts gems from Gemfile.lock.
package ruby

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
)

// Extractor handles Gemfile.lock.
type Extractor struct{}

func (Extractor) Name() string { return "ruby/bundler" }

func (Extractor) FileRequired(p string) bool { return path.Base(p) == "Gemfile.lock" }

var (
	specLine = regexp.MustCompile(`^ {4}([^ ]+) \(([^)]+)\)$`)
	depLine  = regexp.MustCompile(`^ {6}([^ ]+)`)
	rootLine = regexp.MustCompile(`^ {2}([^ !]+)`)
)

func (Extractor) Extract(ctx context.Context, in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	manifest := in.Sibling("Gemfile")
	if !in.Exists(manifest) {
		manifest = in.Path
	}
	proj := &inventory.Project{
		ID: inventory.ProjectID(manifest), Name: in.Dir(), Dir: in.Dir(),
		Manifest: manifest, Lockfile: in.Path, Ecosystem: inventory.RubyGems,
	}
	res := &inventory.Result{Project: proj}

	comps := map[string]*inventory.Component{}
	edges := map[string][]string{}
	var direct []string
	var section, current string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line != "" && line[0] != ' ' {
			section = strings.TrimSpace(line)
			continue
		}
		switch section {
		case "GEM":
			if m := specLine.FindStringSubmatch(line); m != nil {
				// Drop platform suffixes such as "1.13.10-x86_64-linux".
				version, _, _ := strings.Cut(m[2], "-")
				if _, ok := comps[m[1]]; !ok {
					c := inventory.NewLibrary(inventory.RubyGems, m[1], version, manifest, false, false)
					comps[m[1]] = c
					res.Components = append(res.Components, c)
				}
				current = m[1]
			} else if m := depLine.FindStringSubmatch(line); m != nil && current != "" {
				edges[current] = append(edges[current], m[1])
			}
		case "DEPENDENCIES":
			if m := rootLine.FindStringSubmatch(line); m != nil {
				direct = append(direct, m[1])
			}
		}
	}
	for from, tos := range edges {
		for _, to := range tos {
			if t, ok := comps[to]; ok {
				res.Dependencies = append(res.Dependencies, inventory.Dependency{From: comps[from].ID, To: t.ID})
			}
		}
	}
	for _, n := range direct {
		if c, ok := comps[n]; ok {
			c.Direct = true
			res.Dependencies = append(res.Dependencies, inventory.Dependency{From: proj.ID, To: c.ID})
		}
	}
	return res, sc.Err()
}

// Package java extracts Maven coordinates from pom.xml and Gradle builds.
// Without running Maven or Gradle only declared dependencies (and the
// gradle.lockfile, when committed) can be read, so transitive edges are
// limited to what lockfiles record.
package java

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

// Extractor handles pom.xml, build.gradle and build.gradle.kts.
type Extractor struct{}

func (Extractor) Name() string { return "java" }

func (Extractor) FileRequired(p string) bool {
	switch path.Base(p) {
	case "pom.xml", "build.gradle", "build.gradle.kts":
		return true
	}
	return false
}

func (e Extractor) Extract(ctx context.Context, in *inventory.Input) (*inventory.Result, error) {
	if path.Base(in.Path) == "pom.xml" {
		return e.pom(in)
	}
	return e.gradle(in)
}

type builder struct {
	res  *inventory.Result
	seen map[string]bool
}

func newBuilder(in *inventory.Input, name string) *builder {
	return &builder{
		res: &inventory.Result{Project: &inventory.Project{
			ID: inventory.ProjectID(in.Path), Name: name, Dir: in.Dir(),
			Manifest: in.Path, Ecosystem: inventory.Maven,
		}},
		seen: map[string]bool{},
	}
}

func (b *builder) add(group, artifact, version string, dev bool) {
	if group == "" || artifact == "" || version == "" || strings.Contains(version, "$") {
		return
	}
	c := inventory.NewLibrary(inventory.Maven, group+":"+artifact, version, b.res.Project.Manifest, true, dev)
	if b.seen[c.ID] {
		return
	}
	b.seen[c.ID] = true
	b.res.Components = append(b.res.Components, c)
	b.res.Dependencies = append(b.res.Dependencies, inventory.Dependency{From: b.res.Project.ID, To: c.ID})
}

// ---------------------------------------------------------------------------
// Maven
// ---------------------------------------------------------------------------

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type pomFile struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     struct {
		GroupID string `xml:"groupId"`
		Version string `xml:"version"`
	} `xml:"parent"`
	Properties struct {
		Entries []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"properties"`
	Dependencies         []pomDependency `xml:"dependencies>dependency"`
	DependencyManagement []pomDependency `xml:"dependencyManagement>dependencies>dependency"`
}

var propertyRef = regexp.MustCompile(`\$\{([^}]+)\}`)

func (Extractor) pom(in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	var pom pomFile
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, err
	}
	props := map[string]string{
		"project.version":        firstNonEmpty(pom.Version, pom.Parent.Version),
		"project.groupId":        firstNonEmpty(pom.GroupID, pom.Parent.GroupID),
		"project.parent.version": pom.Parent.Version,
	}
	for _, p := range pom.Properties.Entries {
		props[p.XMLName.Local] = strings.TrimSpace(p.Value)
	}
	resolve := func(s string) string {
		for range 5 { // properties may reference properties
			s = propertyRef.ReplaceAllStringFunc(s, func(m string) string {
				if v, ok := props[m[2:len(m)-1]]; ok {
					return v
				}
				return m
			})
		}
		return strings.TrimSpace(s)
	}
	managed := map[string]string{}
	for _, d := range pom.DependencyManagement {
		managed[resolve(d.GroupID)+":"+resolve(d.ArtifactID)] = resolve(d.Version)
	}

	b := newBuilder(in, firstNonEmpty(props["project.groupId"]+":"+pom.ArtifactID, in.Dir()))
	for _, d := range pom.Dependencies {
		g, a := resolve(d.GroupID), resolve(d.ArtifactID)
		v := resolve(d.Version)
		if v == "" {
			v = managed[g+":"+a]
		}
		b.add(g, a, mavenVersion(v), d.Scope == "test" || d.Scope == "provided")
	}
	return b.res, nil
}

// mavenVersion turns a hard requirement "[1.2.3]" into "1.2.3".
func mavenVersion(v string) string {
	return strings.Trim(v, "[]")
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" && v != ":" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Gradle
// ---------------------------------------------------------------------------

// gradleCoordinate matches "group:artifact:version" string literals.
var gradleCoordinate = regexp.MustCompile(`["']([\w.\-]+):([\w.\-]+):([\w.\-+]+)["']`)

var gradleTestConfig = regexp.MustCompile(`(?i)^\s*test\w*\s*[\( ]`)

func (Extractor) gradle(in *inventory.Input) (*inventory.Result, error) {
	b := newBuilder(in, in.Dir())

	// A committed gradle.lockfile pins the full resolved classpath.
	if lp := in.Sibling("gradle.lockfile"); in.Exists(lp) {
		data, err := in.ReadFile(lp)
		if err != nil {
			return nil, err
		}
		b.res.Project.Lockfile = lp
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			coord, configs, ok := strings.Cut(line, "=")
			if !ok || strings.HasPrefix(line, "#") || coord == "empty" {
				continue
			}
			parts := strings.Split(coord, ":")
			if len(parts) == 3 {
				b.add(parts[0], parts[1], parts[2], !strings.Contains(configs, "runtimeClasspath") && !strings.Contains(configs, "compileClasspath"))
			}
		}
		return b.res, sc.Err()
	}

	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		for _, m := range gradleCoordinate.FindAllStringSubmatch(line, -1) {
			b.add(m[1], m[2], m[3], gradleTestConfig.MatchString(line))
		}
	}

	// The version catalog belongs to the root build.
	if in.Exists(in.Sibling("settings.gradle")) || in.Exists(in.Sibling("settings.gradle.kts")) {
		if cp := in.Sibling("gradle/libs.versions.toml"); in.Exists(cp) {
			if err := addVersionCatalog(in, cp, b); err != nil {
				return nil, err
			}
		}
	}
	return b.res, sc.Err()
}

func addVersionCatalog(in *inventory.Input, p string, b *builder) error {
	data, err := in.ReadFile(p)
	if err != nil {
		return err
	}
	var catalog struct {
		Versions  map[string]any `toml:"versions"`
		Libraries map[string]any `toml:"libraries"`
	}
	if _, err := toml.Decode(string(data), &catalog); err != nil {
		return err
	}
	versionOf := func(v any) string {
		switch t := v.(type) {
		case string:
			return t
		case map[string]any:
			if s, ok := t["strictly"].(string); ok {
				return s
			}
			if s, ok := t["require"].(string); ok {
				return s
			}
		}
		return ""
	}
	for _, lib := range catalog.Libraries {
		switch l := lib.(type) {
		case string:
			if parts := strings.Split(l, ":"); len(parts) == 3 {
				b.add(parts[0], parts[1], parts[2], false)
			}
		case map[string]any:
			group, _ := l["group"].(string)
			name, _ := l["name"].(string)
			if module, ok := l["module"].(string); ok {
				group, name, _ = strings.Cut(module, ":")
			}
			version := versionOf(l["version"])
			if ref, ok := l["version.ref"].(string); ok {
				version = versionOf(catalog.Versions[ref])
			}
			if v, ok := l["version"].(map[string]any); ok {
				if ref, ok := v["ref"].(string); ok {
					version = versionOf(catalog.Versions[ref])
				}
			}
			b.add(group, name, version, false)
		}
	}
	return nil
}

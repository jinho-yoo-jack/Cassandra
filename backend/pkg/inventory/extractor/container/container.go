// Package container extracts container images from Dockerfiles, Compose
// files and Kubernetes manifests, and maps well known server images (nginx,
// httpd, ...) to the process they run so they can be matched against NVD.
package container

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
)

// Extractor handles Dockerfile*, compose files and Kubernetes manifests.
type Extractor struct{}

func (Extractor) Name() string { return "container" }

var composeFile = regexp.MustCompile(`^(docker-)?compose[^/]*\.ya?ml$`)

// lockLikeYAML are YAML files that are never Kubernetes manifests.
var lockLikeYAML = map[string]bool{"pnpm-lock.yaml": true, "pnpm-workspace.yaml": true, ".gitlab-ci.yml": true}

func (Extractor) FileRequired(p string) bool {
	base := path.Base(p)
	switch {
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".Dockerfile") || base == "Containerfile":
		return true
	case composeFile.MatchString(base):
		return true
	case strings.HasPrefix(p, ".github/"):
		return false
	case (strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")) && !lockLikeYAML[base]:
		return true
	}
	return false
}

func (e Extractor) Extract(ctx context.Context, in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	base := path.Base(in.Path)
	var images []string
	switch {
	case strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"):
		if composeFile.MatchString(base) {
			images = composeImages(data)
		} else {
			images = kubernetesImages(data)
		}
	default:
		images = dockerfileImages(data)
	}
	if len(images) == 0 {
		return nil, nil
	}

	proj := &inventory.Project{
		ID: inventory.ProjectID(in.Path), Name: in.Path, Dir: in.Dir(),
		Manifest: in.Path, Ecosystem: inventory.Image,
	}
	res := &inventory.Result{Project: proj}
	seen := map[string]bool{}
	for _, img := range images {
		ref := ParseImageRef(img)
		if ref == nil {
			continue
		}
		c := NewImageComponent(ref, in.Path)
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		res.Components = append(res.Components, c)
		res.Dependencies = append(res.Dependencies, inventory.Dependency{From: proj.ID, To: c.ID})
		if p := ProcessFor(ref, in.Path); p != nil {
			res.Components = append(res.Components, p)
			res.Dependencies = append(res.Dependencies, inventory.Dependency{From: c.ID, To: p.ID})
		}
	}
	return res, nil
}

// NewImageComponent returns the container component of an image reference.
func NewImageComponent(ref *inventory.ImageRef, location string) *inventory.Component {
	version := ref.Tag
	if version == "" {
		version = ref.Digest
	}
	purl := inventory.PURL(inventory.Image, ref.Repository, version)
	return &inventory.Component{
		ID: purl, PURL: purl, Type: inventory.TypeContainer, Name: ref.Repository,
		Version: version, Ecosystem: inventory.Image, Direct: true,
		Locations: []string{location}, Image: ref,
	}
}

// ---------------------------------------------------------------------------
// Dockerfile
// ---------------------------------------------------------------------------

var argLine = regexp.MustCompile(`(?i)^ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)`)
var varRef = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)(:-[^}]*)?\}?`)

// dockerfileImages returns the base images of every stage, skipping
// references to earlier stages and scratch.
func dockerfileImages(data []byte) []string {
	args := map[string]string{}
	stages := map[string]bool{}
	var images []string
	for _, line := range logicalLines(data) {
		if m := argLine.FindStringSubmatch(line); m != nil {
			args[m[1]] = strings.Trim(m[2], `"'`)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		rest := fields[1:]
		for len(rest) > 0 && strings.HasPrefix(rest[0], "--") {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			continue
		}
		img := varRef.ReplaceAllStringFunc(rest[0], func(m string) string {
			sm := varRef.FindStringSubmatch(m)
			if v, ok := args[sm[1]]; ok {
				return v
			}
			return strings.TrimPrefix(sm[2], ":-")
		})
		if len(rest) >= 3 && strings.EqualFold(rest[1], "AS") {
			stages[strings.ToLower(rest[2])] = true
		}
		if img == "scratch" || stages[strings.ToLower(img)] || strings.Contains(img, "$") {
			continue
		}
		images = append(images, img)
	}
	return images
}

// logicalLines joins backslash continued lines and drops comments.
func logicalLines(data []byte) []string {
	var (
		out []string
		cur strings.Builder
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			cur.WriteString(strings.TrimSuffix(line, `\`) + " ")
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	return out
}

// DockerfileFromLines returns the line numbers (0-based) and image references
// of FROM instructions, used by the image fixer to rewrite tags.
func DockerfileFromLines(data []byte) map[int]string {
	out := map[int]string{}
	for i, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		for _, f := range fields[1:] {
			if !strings.HasPrefix(f, "--") {
				out[i] = f
				break
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Compose and Kubernetes
// ---------------------------------------------------------------------------

func composeImages(data []byte) []string {
	var doc struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var out []string
	for _, s := range doc.Services {
		if s.Image != "" && !strings.Contains(s.Image, "$") {
			out = append(out, s.Image)
		}
	}
	return out
}

var docSeparator = regexp.MustCompile(`(?m)^---\s*$`)

// kubernetesImages returns container images of every manifest in a
// multi-document YAML file. Documents without apiVersion and kind, and Helm
// templates that are not valid YAML, are ignored.
func kubernetesImages(data []byte) []string {
	var out []string
	for _, doc := range docSeparator.Split(string(data), -1) {
		var obj map[string]any
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil || obj["apiVersion"] == nil || obj["kind"] == nil {
			continue
		}
		collectImages(obj, &out)
	}
	return out
}

func collectImages(v any, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == "image" {
				if s, ok := val.(string); ok && s != "" {
					*out = append(*out, s)
				}
				continue
			}
			collectImages(val, out)
		}
	case []any:
		for _, val := range t {
			collectImages(val, out)
		}
	}
}

// ---------------------------------------------------------------------------
// Image references and processes
// ---------------------------------------------------------------------------

// ParseImageRef parses [registry/]repository[:tag][@digest]. Official
// Docker Hub images get the "library/" prefix.
func ParseImageRef(s string) *inventory.ImageRef {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	ref := &inventory.ImageRef{}
	if i := strings.Index(s, "@"); i >= 0 {
		ref.Digest, s = s[i+1:], s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		ref.Tag, s = s[i+1:], s[:i]
	}
	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		ref.Registry, s = parts[0], parts[1]
	}
	if ref.Registry == "" && !strings.Contains(s, "/") {
		s = "library/" + s
	}
	ref.Repository = s
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = "latest"
	}
	return ref
}

// String renders the reference.
func String(ref *inventory.ImageRef) string {
	var b strings.Builder
	if ref.Registry != "" {
		b.WriteString(ref.Registry + "/")
	}
	b.WriteString(strings.TrimPrefix(ref.Repository, "library/"))
	if ref.Tag != "" {
		b.WriteString(":" + ref.Tag)
	}
	if ref.Digest != "" {
		b.WriteString("@" + ref.Digest)
	}
	return b.String()
}

// KnownProcess describes a server image whose version can be matched with
// NVD through its CPE.
type KnownProcess struct {
	Name string
	// CPEs are vendor:product pairs; nginx is listed under two vendors in
	// NVD because F5 took over the CPE in 2022.
	CPEs []string
	// VersionCommand prints the version inside the container.
	VersionCommand []string
	// ConfigTestCommand validates the configuration, if the server has one.
	ConfigTestCommand []string
	// Port is the default listening port used for the HTTP health check.
	Port int
}

// KnownProcesses is keyed by the last path element of the image repository.
var KnownProcesses = map[string]KnownProcess{
	"nginx":              {Name: "nginx", CPEs: []string{"f5:nginx", "nginx:nginx"}, VersionCommand: []string{"nginx", "-v"}, ConfigTestCommand: []string{"nginx", "-t"}, Port: 80},
	"nginx-unprivileged": {Name: "nginx", CPEs: []string{"f5:nginx", "nginx:nginx"}, VersionCommand: []string{"nginx", "-v"}, ConfigTestCommand: []string{"nginx", "-t"}, Port: 8080},
	"httpd":              {Name: "apache-httpd", CPEs: []string{"apache:http_server"}, VersionCommand: []string{"httpd", "-v"}, ConfigTestCommand: []string{"httpd", "-t"}, Port: 80},
	"apache":             {Name: "apache-httpd", CPEs: []string{"apache:http_server"}, VersionCommand: []string{"httpd", "-v"}, ConfigTestCommand: []string{"httpd", "-t"}, Port: 80},
	"tomcat":             {Name: "apache-tomcat", CPEs: []string{"apache:tomcat"}, VersionCommand: []string{"catalina.sh", "version"}, Port: 8080},
	"haproxy":            {Name: "haproxy", CPEs: []string{"haproxy:haproxy"}, VersionCommand: []string{"haproxy", "-v"}},
	"traefik":            {Name: "traefik", CPEs: []string{"traefik:traefik"}, VersionCommand: []string{"traefik", "version"}},
	"caddy":              {Name: "caddy", CPEs: []string{"caddyserver:caddy"}, VersionCommand: []string{"caddy", "version"}, Port: 80},
	"envoy":              {Name: "envoy", CPEs: []string{"envoyproxy:envoy"}, VersionCommand: []string{"envoy", "--version"}},
	"redis":              {Name: "redis", CPEs: []string{"redis:redis"}, VersionCommand: []string{"redis-server", "--version"}},
	"postgres":           {Name: "postgresql", CPEs: []string{"postgresql:postgresql"}, VersionCommand: []string{"postgres", "--version"}},
	"mysql":              {Name: "mysql", CPEs: []string{"oracle:mysql"}, VersionCommand: []string{"mysqld", "--version"}},
	"mariadb":            {Name: "mariadb", CPEs: []string{"mariadb:mariadb"}, VersionCommand: []string{"mariadbd", "--version"}},
	"mongo":              {Name: "mongodb", CPEs: []string{"mongodb:mongodb"}, VersionCommand: []string{"mongod", "--version"}},
	"memcached":          {Name: "memcached", CPEs: []string{"memcached:memcached"}, VersionCommand: []string{"memcached", "-V"}},
	"rabbitmq":           {Name: "rabbitmq", CPEs: []string{"vmware:rabbitmq", "pivotal_software:rabbitmq"}, VersionCommand: []string{"rabbitmq-diagnostics", "server_version"}},
	"node":               {Name: "node.js", CPEs: []string{"nodejs:node.js"}, VersionCommand: []string{"node", "--version"}},
}

var tagVersion = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,3})`)

// VersionFromTag returns the leading version of an image tag:
// "1.25.3-alpine" -> "1.25.3". Floating tags such as "latest" yield "".
func VersionFromTag(tag string) string {
	m := tagVersion.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	return m[1]
}

// LookupProcess returns the known process of an image repository.
func LookupProcess(repository string) (KnownProcess, bool) {
	p, ok := KnownProcesses[path.Base(repository)]
	return p, ok
}

// ProcessFor returns the process component run by a known server image, or
// nil. Floating tags ("latest", "5", "1.25") resolve to different releases
// over time, so they get a process node without version: matching "5"
// against NVD ranges would report every 5.x CVE. The graph flags them as
// unpinned instead.
func ProcessFor(ref *inventory.ImageRef, location string) *inventory.Component {
	known, ok := LookupProcess(ref.Repository)
	if !ok {
		return nil
	}
	version := VersionFromTag(ref.Tag)
	if strings.Count(version, ".") < 2 {
		version = ""
	}
	purl := inventory.PURL(inventory.Process, known.Name, version)
	return &inventory.Component{
		ID: purl, PURL: purl, Type: inventory.TypeApplication, Name: known.Name,
		Version: version, Ecosystem: inventory.Process, CPEs: known.CPEs,
		Direct: true, Locations: []string{location},
	}
}

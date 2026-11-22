package all

import (
	"context"
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

var repo = fstest.MapFS{
	"go.mod": {Data: []byte(`module example.com/app

go 1.23

toolchain go1.23.4

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/net v0.10.0 // indirect
	example.com/local v0.0.0
)

replace example.com/local => ../local
`)},
	"web/package.json": {Data: []byte(`{"name":"web","dependencies":{"express":"^4.17.0"},"devDependencies":{"vitest":"^1.0.0"}}`)},
	"web/package-lock.json": {Data: []byte(`{"lockfileVersion":3,"packages":{
		"":{"name":"web","dependencies":{"express":"^4.17.0"},"devDependencies":{"vitest":"^1.0.0"}},
		"node_modules/express":{"version":"4.17.1","dependencies":{"body-parser":"1.19.0"}},
		"node_modules/body-parser":{"version":"1.19.0"},
		"node_modules/vitest":{"version":"1.0.0","dev":true}}}`)},
	"pnpm-app/package.json": {Data: []byte(`{"name":"pnpm-app","dependencies":{"@scope/lib":"^2.0.0"}}`)},
	"pnpm-app/pnpm-lock.yaml": {Data: []byte(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@scope/lib':
        specifier: ^2.0.0
        version: 2.1.0(react@19.0.0)
packages:
  '@scope/lib@2.1.0':
    resolution: {integrity: sha512-x}
  react@19.0.0:
    resolution: {integrity: sha512-y}
snapshots:
  '@scope/lib@2.1.0(react@19.0.0)':
    dependencies:
      react: 19.0.0
  react@19.0.0: {}
`)},
	"yarn-app/package.json": {Data: []byte(`{"name":"yarn-app","dependencies":{"lodash":"^4.17.0"}}`)},
	"yarn-app/yarn.lock": {Data: []byte(`# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"
`)},
	"api/requirements.txt": {Data: []byte("Django==3.2.0\nrequests[security]>=2.25.0 ; python_version > '3'\n# comment\n-e .\n")},
	"svc/pyproject.toml":   {Data: []byte("[project]\nname = \"svc\"\ndependencies = [\"jinja2>=3\"]\n")},
	"svc/uv.lock": {Data: []byte(`version = 1

[[package]]
name = "svc"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "jinja2" }]

[[package]]
name = "jinja2"
version = "3.1.2"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "markupsafe" }]

[[package]]
name = "markupsafe"
version = "2.1.3"
source = { registry = "https://pypi.org/simple" }
`)},
	"java/pom.xml": {Data: []byte(`<project><groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0</version>
<properties><log4j.version>2.14.1</log4j.version></properties>
<dependencies>
 <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
 <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
</dependencies></project>`)},
	"rs/Cargo.lock": {Data: []byte(`version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)},
	"deploy/Dockerfile":                 {Data: []byte("ARG NGINX_VERSION=1.25.3\nFROM golang:1.21 AS build\nFROM nginx:${NGINX_VERSION}-alpine\nCOPY --from=build /app /app\n")},
	"deploy/k8s.yaml":                   {Data: []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: web\n        image: httpd:2.4.58\n---\nnot: a manifest\nimage: ignored:1\n")},
	"node_modules/ignored/package.json": {Data: []byte(`{"name":"ignored","dependencies":{"x":"1.0.0"}}`)},
}

func TestExtractors(t *testing.T) {
	inv, err := inventory.Extract(context.Background(), repo, Extractors(Options{}), slog.Default())
	if err != nil {
		t.Fatal(err)
	}

	type want struct {
		direct bool
		dev    bool
	}
	tests := []struct {
		id   string
		want want
	}{
		{"pkg:golang/github.com/gin-gonic/gin@v1.9.0", want{direct: true}},
		{"pkg:golang/golang.org/x/net@v0.10.0", want{}},
		{"pkg:golang/stdlib@1.23.4", want{direct: true}},
		{"pkg:npm/express@4.17.1", want{direct: true}},
		{"pkg:npm/body-parser@1.19.0", want{}},
		{"pkg:npm/vitest@1.0.0", want{direct: true, dev: true}},
		{"pkg:npm/%40scope/lib@2.1.0", want{direct: true}},
		{"pkg:npm/react@19.0.0", want{}},
		{"pkg:npm/lodash@4.17.20", want{direct: true}},
		{"pkg:pypi/django@3.2.0", want{direct: true}},
		{"pkg:pypi/requests@2.25.0", want{direct: true}},
		{"pkg:pypi/jinja2@3.1.2", want{direct: true}},
		{"pkg:pypi/markupsafe@2.1.3", want{}},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", want{direct: true}},
		{"pkg:maven/junit/junit@4.12", want{direct: true, dev: true}},
		{"pkg:cargo/serde@1.0.100", want{direct: true}},
		{"pkg:docker/library/nginx@1.25.3-alpine", want{direct: true}},
		{"pkg:generic/nginx@1.25.3", want{direct: true}},
		{"pkg:docker/library/httpd@2.4.58", want{direct: true}},
		{"pkg:generic/apache-httpd@2.4.58", want{direct: true}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			c := inv.Component(tt.id)
			if c == nil {
				t.Fatalf("component not found")
			}
			if c.Direct != tt.want.direct || c.Dev != tt.want.dev {
				t.Errorf("direct=%v dev=%v, want %+v", c.Direct, c.Dev, tt.want)
			}
		})
	}

	// Local replaces, installed packages and non-manifest YAML documents
	// must not appear.
	for _, id := range []string{"pkg:golang/example.com/local@v0.0.0", "pkg:npm/x@1.0.0", "pkg:docker/library/ignored@1"} {
		if inv.Component(id) != nil {
			t.Errorf("unexpected component %s", id)
		}
	}

	edges := []inventory.Dependency{
		{From: "pkg:npm/express@4.17.1", To: "pkg:npm/body-parser@1.19.0"},
		{From: "pkg:npm/%40scope/lib@2.1.0", To: "pkg:npm/react@19.0.0"},
		{From: "pkg:pypi/jinja2@3.1.2", To: "pkg:pypi/markupsafe@2.1.3"},
		{From: "pkg:docker/library/nginx@1.25.3-alpine", To: "pkg:generic/nginx@1.25.3"},
		{From: "project:web/package.json", To: "pkg:npm/express@4.17.1"},
	}
	have := map[inventory.Dependency]bool{}
	for _, d := range inv.Dependencies {
		have[d] = true
	}
	for _, e := range edges {
		if !have[e] {
			t.Errorf("missing edge %s -> %s", e.From, e.To)
		}
	}

	if path := inv.PathTo("pkg:npm/body-parser@1.19.0"); len(path) != 3 || path[0] != "project:web/package.json" {
		t.Errorf("PathTo = %v", path)
	}
}

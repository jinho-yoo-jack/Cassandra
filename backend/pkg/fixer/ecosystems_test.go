package fixer

import (
	"strings"
	"testing"

	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory/extractor/container"
)

func TestPinRequirement(t *testing.T) {
	tests := []struct {
		name, content, pkg, target, want string
	}{
		{"pinned", "Django==3.2.0\nrequests==2.0\n", "django", "3.2.25", "Django==3.2.25\nrequests==2.0\n"},
		{"extras and markers", "requests[security]>=2.0 ; python_version > '3'\n", "requests", "2.32.0", "requests[security]==2.32.0 ; python_version > '3'\n"},
		{"transitive appended", "flask==2.0", "Jinja2", "3.1.4", "flask==2.0\nJinja2>=3.1.4  # vulngraph: transitive dependency pin\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pinRequirement(tt.content, tt.pkg, tt.target); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBumpPom(t *testing.T) {
	literal := `<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>`
	property := `<project><properties><log4j.version>2.14.1</log4j.version></properties><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency></dependencies></project>`
	transitive := `<project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies></project>`

	tests := []struct {
		name, content, mustContain string
	}{
		{"literal", literal, "<version>2.17.1</version>"},
		{"property", property, "<log4j.version>2.17.1</log4j.version>"},
		{"transitive uses dependencyManagement", transitive, "<dependencyManagement>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bumpPom(tt.content, "org.apache.logging.log4j", "log4j-core", "2.14.1", "2.17.1")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(got, tt.mustContain) {
				t.Errorf("result does not contain %q:\n%s", tt.mustContain, got)
			}
		})
	}
}

func TestImageRewrite(t *testing.T) {
	if got := ReplaceTagVersion("1.25.3-alpine", "1.27.1"); got != "1.27.1-alpine" {
		t.Errorf("ReplaceTagVersion = %q", got)
	}
	if got := ReplaceTagVersion("latest", "1.27.1"); got != "" {
		t.Errorf("floating tag should not be bumped, got %q", got)
	}

	from := container.ParseImageRef("nginx:1.25.3-alpine")
	to := container.ParseImageRef("nginx:1.27.1-alpine")
	tests := []struct{ name, in, want string }{
		{"dockerfile", "FROM nginx:1.25.3-alpine AS web\n", "FROM nginx:1.27.1-alpine AS web\n"},
		{"compose", "  image: \"nginx:1.25.3-alpine\"\n", "  image: \"nginx:1.27.1-alpine\"\n"},
		{"explicit library prefix", "image: docker.io/library/nginx:1.25.3-alpine\n", "image: docker.io/library/nginx:1.27.1-alpine\n"},
		{"other image untouched", "FROM mynginx:1.25.3-alpine\n", "FROM mynginx:1.25.3-alpine\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replaceImageRef(tt.in, from, to); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
	arg := "ARG NGINX_VERSION=1.25.3\nFROM nginx:${NGINX_VERSION}-alpine\n"
	if got := replaceArgDefault(arg, "1.25.3", "1.27.1"); !strings.HasPrefix(got, "ARG NGINX_VERSION=1.27.1\n") {
		t.Errorf("replaceArgDefault = %q", got)
	}
}

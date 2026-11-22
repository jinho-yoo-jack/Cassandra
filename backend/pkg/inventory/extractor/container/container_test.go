package container

import "testing"

func TestProcessFor(t *testing.T) {
	tests := []struct {
		image       string
		wantName    string
		wantVersion string
	}{
		{"nginx:1.25.3-alpine", "nginx", "1.25.3"},
		{"registry.example.com/team/nginx:1.27.1", "nginx", "1.27.1"},
		{"httpd:2.4.58@sha256:abc", "apache-httpd", "2.4.58"},
		{"mysql:5", "mysql", ""},    // floating major tag
		{"nginx:1.25", "nginx", ""}, // floating minor tag
		{"nginx", "nginx", ""},      // implicit latest
	}
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			p := ProcessFor(ParseImageRef(tt.image), "Dockerfile")
			if p == nil || p.Name != tt.wantName || p.Version != tt.wantVersion {
				t.Fatalf("ProcessFor(%q) = %+v, want %s@%q", tt.image, p, tt.wantName, tt.wantVersion)
			}
		})
	}
	if ProcessFor(ParseImageRef("alpine:3.20"), "Dockerfile") != nil {
		t.Error("alpine is not a known server process")
	}
}

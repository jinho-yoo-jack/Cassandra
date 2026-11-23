package remediation

import (
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

func TestFindSame(t *testing.T) {
	lib := func(version string, direct bool) *inventory.Component {
		return inventory.NewLibrary(inventory.NPM, "lodash", version, "package.json", direct, false)
	}
	// After a fix, npm keeps a nested copy for a package that pins its own
	// range (here nyc → lodash 4.17.10).
	inv := &inventory.Inventory{Components: []*inventory.Component{lib("4.17.10", false), lib("4.18.0", true)}}

	tests := []struct {
		name        string
		original    *inventory.Component
		wantVersion string
	}{
		{"direct fix verifies the declared copy", lib("4.17.4", true), "4.18.0"},
		{"transitive fix verifies the lowest copy", lib("4.17.4", false), "4.17.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findSame(inv, tt.original)
			if got == nil || got.Version != tt.wantVersion {
				t.Fatalf("findSame = %+v, want version %s", got, tt.wantVersion)
			}
		})
	}
	if findSame(inv, inventory.NewLibrary(inventory.NPM, "lodash", "1.0.0", "other/package.json", true, false)) != nil {
		t.Error("components in other manifests must not match")
	}
}

package javascript

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

func TestAncestorLockDoesNotHideUnresolvedDeclarations(t *testing.T) {
	fsys := fstest.MapFS{
		"package.json":                {Data: []byte(`{}`)},
		"package-lock.json":           {Data: []byte(`{"lockfileVersion":3,"packages":{"":{}}}`)},
		"packages/child/package.json": {Data: []byte(`{"dependencies":{"lodash":"4.17.20"}}`)},
	}
	_, warnings, err := inventory.ExtractWithDiagnostics(context.Background(), fsys, []inventory.Extractor{Extractor{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "packages/child/package.json") {
		t.Fatalf("unresolved child silently skipped: %v", warnings)
	}
}

func TestDependencyDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, lock, data string
		warn                       bool
		components                 int
	}{
		{"npm missing transitive", `{}`, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0","dependencies":{"missing":"1.0.0"}}}}`, true, 1},
		{"pnpm missing transitive", `{}`, "pnpm-lock.yaml", "lockfileVersion: '9.0'\nsnapshots:\n  a@1.0.0:\n    dependencies:\n      missing: 1.0.0\n", true, 1},
		{"yarn missing transitive", `{}`, "yarn.lock", "a@^1:\n  version \"1.0.0\"\n  dependencies:\n    missing \"^1\"\n", true, 1},
		{"npm invalid structure", `{"dependencies":{"lodash":"4.17.20"}}`, "package-lock.json", `{}`, true, 0},
		{"npm missing declaration", `{"dependencies":{"lodash":"4.17.20"}}`, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{}}}`, true, 0},
		{"npm partial", `{"dependencies":{"lodash":"4.17.20","missing":"1.0.0"}}`, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}}}`, true, 1},
		{"npm unresolved entry", `{}`, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{}}}`, true, 0},
		{"pnpm invalid structure", `{}`, "pnpm-lock.yaml", `{}`, true, 0},
		{"pnpm missing", `{"dependencies":{"lodash":"4.17.20"}}`, "pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .: {}\n", true, 0},
		{"yarn malformed", `{}`, "yarn.lock", "???\n", true, 0},
		{"yarn missing", `{"dependencies":{"lodash":"4.17.20"}}`, "yarn.lock", "# yarn lockfile v1\n", true, 0},
		{"missing lock unpinned", `{"dependencies":{"lodash":"latest"}}`, "", "", true, 0},
		{"missing lock range", `{"dependencies":{"lodash":"^4.17.20"}}`, "", "", true, 1},
		{"empty", `{}`, "", "", false, 0},
		{"empty npm lock", `{}`, "package-lock.json", `{"lockfileVersion":3,"packages":{"":{}}}`, false, 0},
		{"empty pnpm lock", `{}`, "pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .: {}\n", false, 0},
		{"empty yarn lock", `{}`, "yarn.lock", "# yarn lockfile v1\n", false, 0},
		{"local workspace", `{"dependencies":{"local":"workspace:*"}}`, "", "", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{"package.json": {Data: []byte(tc.manifest)}}
			if tc.lock != "" {
				fsys[tc.lock] = &fstest.MapFile{Data: []byte(tc.data)}
			}
			inv, warnings, err := inventory.ExtractWithDiagnostics(context.Background(), fsys, []inventory.Extractor{Extractor{}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if (len(warnings) > 0) != tc.warn {
				t.Errorf("warnings=%v, want warning=%v", warnings, tc.warn)
			}
			if len(warnings) > 0 && !strings.Contains(warnings[0], "inventory: javascript/npm package.json:") {
				t.Errorf("missing context: %v", warnings)
			}
			if len(inv.Components) != tc.components {
				t.Errorf("got %d components, want %d", len(inv.Components), tc.components)
			}
		})
	}
}

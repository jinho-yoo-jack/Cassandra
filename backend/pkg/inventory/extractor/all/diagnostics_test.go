package all

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/python"
)

func TestRequirementsDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, data, want string
		components       int
	}{
		{"malformed", "???\n", "line 1", 0},
		{"unpinned", "requests\n", "requests", 0},
		{"include", "-r base.txt\n", "line 1", 0},
		{"vcs", "git+https://example.com/repo.git\n", "line 1", 0},
		{"range", "requests>=2.25.0\n", "requests", 1},
		{"mixed", "Django==3.2.0\nrequests\n", "requests", 1},
		{"empty", "# no dependencies\n", "", 0},
		{"resolved", "requests[security]==2.25.0 ; python_version > '3'\n", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{"requirements.txt": {Data: []byte(tc.data)}}
			inv, warnings, err := inventory.ExtractWithDiagnostics(context.Background(), fsys, []inventory.Extractor{python.Extractor{}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Components) != tc.components {
				t.Errorf("components=%v, want %d", inv.Components, tc.components)
			}
			if tc.want == "" {
				if len(warnings) > 0 {
					t.Fatalf("unexpected warnings: %v", warnings)
				}
				return
			}
			joined := strings.Join(warnings, "\n")
			if !strings.Contains(joined, "inventory: python requirements.txt:") || !strings.Contains(joined, tc.want) {
				t.Fatalf("missing actionable diagnostic %q: %v", tc.want, warnings)
			}
		})
	}
}

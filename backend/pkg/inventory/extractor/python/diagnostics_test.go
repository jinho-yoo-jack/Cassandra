package python

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
)

func TestManifestDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, data, lock, lockData string
		warn                                 bool
		components                           int
	}{
		{"pyproject URL", "pyproject.toml", "[project]\ndependencies=['requests @ https://example.com/a.whl']\n", "", "", true, 0},
		{"pipfile local lock", "Pipfile.lock", `{"default":{"local":{"path":"."}},"develop":{}}`, "", "", false, 0},
		{"pipfile range lock", "Pipfile.lock", `{"default":{"requests":{"version":">=2.0"}},"develop":{}}`, "", "", true, 0},
		{"pyproject unpinned", "pyproject.toml", "[project]\ndependencies=['requests']\n", "", "", true, 0},
		{"pyproject malformed dependency", "pyproject.toml", "[project]\ndependencies=['???']\n", "", "", true, 0},
		{"pyproject optional", "pyproject.toml", "[project.optional-dependencies]\ntest=['pytest']\n", "", "", true, 0},
		{"poetry dev", "pyproject.toml", "[tool.poetry.group.dev.dependencies]\npytest='*'\n", "", "", true, 0},
		{"uv missing declaration", "pyproject.toml", "[project]\ndependencies=['requests','flask']\n", "uv.lock", "version=1\n[[package]]\nname='requests'\nversion='2.25.0'\n", true, 1},
		{"uv malformed structure", "pyproject.toml", "[project]\nname='empty'\n", "uv.lock", "unrelated=true\n", true, 0},
		{"uv missing version", "pyproject.toml", "[project]\nname='app'\n", "uv.lock", "version=1\n[[package]]\nname='requests'\n", true, 0},
		{"uv local", "pyproject.toml", "[project]\ndependencies=['local']\n", "uv.lock", "version=1\n[[package]]\nname='local'\nsource={editable='../local'}\n", false, 0},
		{"pyproject empty", "pyproject.toml", "[project]\nname='empty'\ndependencies=[]\n", "", "", false, 0},
		{"pipfile missing lock", "Pipfile", "[packages]\nrequests='*'\n", "", "", true, 0},
		{"pipfile empty", "Pipfile", "[packages]\n", "", "", false, 0},
		{"pipfile invalid structure", "Pipfile.lock", `{}`, "", "", true, 0},
		{"pipfile unversioned", "Pipfile.lock", `{"default":{"requests":{"git":"https://example.com/repo"}},"develop":{}}`, "", "", true, 0},
		{"pipfile partial", "Pipfile.lock", `{"default":{"requests":{"version":"==2.25.0"},"missing":{}},"develop":{}}`, "", "", true, 1},
		{"pipfile stale lock", "Pipfile", "[packages]\nrequests='*'\n", "Pipfile.lock", `{"default":{},"develop":{}}`, true, 0},
		{"pipfile empty lock", "Pipfile.lock", `{"default":{},"develop":{}}`, "", "", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{tc.manifest: {Data: []byte(tc.data)}}
			if tc.lock != "" {
				fsys[tc.lock] = &fstest.MapFile{Data: []byte(tc.lockData)}
			}
			inv, warnings, err := inventory.ExtractWithDiagnostics(context.Background(), fsys, []inventory.Extractor{Extractor{}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if (len(warnings) > 0) != tc.warn {
				t.Errorf("warnings=%v, want warning=%v", warnings, tc.warn)
			}
			if len(inv.Components) != tc.components {
				t.Errorf("got %d components, want %d", len(inv.Components), tc.components)
			}
		})
	}
}

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
)

func TestIncompleteDeclarationsCannotPassCLI(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		link  bool
		want  int
	}{
		{"invalid-requirement", map[string]string{"requirements.txt": "???\n"}, false, 2},
		{"unversioned-requirement", map[string]string{"requirements.txt": "requests\n"}, false, 2},
		{"empty-lock-with-declarations", map[string]string{"package.json": `{"name":"fixture","dependencies":{"lodash":"4.17.20"}}`, "package-lock.json": "{}"}, false, 2},
		{"linked-manifest", map[string]string{"package.json": `{"name":"fixture"}`, "deps.txt": "requests==2.19.1\n"}, true, 2},
		{"genuinely-empty-project", map[string]string{"package.json": `{"name":"fixture","dependencies":{}}`}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, dir, out := fixtureArgs(t, fixtureServer(t, "clean"))
			if err := os.Remove(filepath.Join(dir, "requirements.txt")); err != nil {
				t.Fatal(err)
			}
			for name, data := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.link {
				if err := os.Symlink("deps.txt", filepath.Join(dir, "requirements.txt")); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			if code := Execute(context.Background(), args, &stdout, &stderr); code != tc.want {
				t.Fatalf("code=%d want=%d stderr=%s", code, tc.want, &stderr)
			}
			data, err := os.ReadFile(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var r report.Report
			if err := json.Unmarshal(data, &r); err != nil {
				t.Fatal(err)
			}
			if tc.want == 2 && len(r.Match.Warnings) == 0 {
				t.Fatal("incomplete scan lost diagnostics")
			}
			if tc.want == 0 && len(r.Match.Warnings) != 0 {
				t.Fatalf("empty project unexpectedly incomplete: %v", r.Match.Warnings)
			}
		})
	}
}

func TestCLIOutputDirectoryLinkPreservesVictim(t *testing.T) {
	args, dir, _ := fixtureArgs(t, fixtureServer(t, "clean"))
	victim := t.TempDir()
	sentinel := filepath.Join(victim, "report.json")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "cassandra-results")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	args = append(args, "--output-dir", link)
	var out bytes.Buffer
	if code := Execute(context.Background(), args, &out, &out); code != 2 {
		t.Fatalf("linked output code=%d %s", code, &out)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
		t.Fatalf("victim changed: %q %v", data, err)
	}
}

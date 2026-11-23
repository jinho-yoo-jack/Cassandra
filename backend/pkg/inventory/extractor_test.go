package inventory

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

type failingExtractor struct{ err error }

func (f failingExtractor) Name() string                                     { return "broken" }
func (f failingExtractor) FileRequired(p string) bool                       { return p == "manifest" }
func (f failingExtractor) Extract(context.Context, *Input) (*Result, error) { return nil, f.err }

type diagnosticExtractor struct{}

type siblingExtractor struct{ diagnosticExtractor }

func (siblingExtractor) Extract(_ context.Context, in *Input) (*Result, error) {
	_ = in.Exists("lock.json")
	return &Result{Project: &Project{ID: "p"}}, nil
}

func TestInaccessibleSiblingCannotMasqueradeAsAbsent(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "lock.json")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, warnings, err := ExtractWithDiagnostics(context.Background(), root.FS(), []Extractor{siblingExtractor{}}, nil)
	if err != nil || len(warnings) == 0 {
		t.Fatalf("unreadable sibling was silently treated as absent: %v %v", warnings, err)
	}
}

func (diagnosticExtractor) Name() string               { return "diagnostic" }
func (diagnosticExtractor) FileRequired(p string) bool { return p == "manifest" }
func (diagnosticExtractor) Extract(context.Context, *Input) (*Result, error) {
	return &Result{Project: &Project{ID: "p"}, Warnings: []string{"unresolved declaration"}}, nil
}

func TestExtractionPreservesParserDiagnostics(t *testing.T) {
	inv, warnings, err := ExtractWithDiagnostics(context.Background(), fstest.MapFS{"manifest": &fstest.MapFile{}}, []Extractor{diagnosticExtractor{}}, nil)
	if err != nil || len(inv.Projects) != 1 || len(warnings) != 1 || !strings.HasPrefix(warnings[0], "inventory:") {
		t.Fatalf("inventory=%v warnings=%v err=%v", inv, warnings, err)
	}
}

func TestSkippedManifestLinksAreIncomplete(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte("dependencies"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("data", filepath.Join(dir, "manifest")); err != nil {
		t.Fatal(err)
	}
	_, warnings, err := ExtractWithDiagnostics(context.Background(), os.DirFS(dir), []Extractor{diagnosticExtractor{}}, nil)
	if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "manifest") {
		t.Fatalf("skipped manifest not diagnosed: %v %v", warnings, err)
	}
}

func TestExtractionDiagnostics(t *testing.T) {
	repo := fstest.MapFS{"manifest": &fstest.MapFile{Data: []byte("invalid")}}
	inv, warnings, err := ExtractWithDiagnostics(context.Background(), repo, []Extractor{failingExtractor{errors.New("malformed manifest")}}, slog.Default())
	if err != nil || inv == nil || len(warnings) != 1 || !strings.Contains(warnings[0], "manifest") {
		t.Fatalf("inventory=%v warnings=%v err=%v", inv, warnings, err)
	}
}

func TestExtractionRejectsMissingRoot(t *testing.T) {
	_, _, err := ExtractWithDiagnostics(context.Background(), os.DirFS(filepath.Join(t.TempDir(), "missing")), nil, slog.Default())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want missing root error, got %v", err)
	}
}

func TestExtractionPropagatesCancellation(t *testing.T) {
	for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(want.Error(), func(t *testing.T) {
			repo := fstest.MapFS{"manifest": &fstest.MapFile{}}
			_, _, err := ExtractWithDiagnostics(context.Background(), repo, []Extractor{failingExtractor{want}}, slog.Default())
			if !errors.Is(err, want) {
				t.Fatalf("want %v, got %v", want, err)
			}
		})
	}
}

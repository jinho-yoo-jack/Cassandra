package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/all"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
)

type matcherFunc func(context.Context, *inventory.Inventory) (*vulndb.Result, error)

func (f matcherFunc) Match(ctx context.Context, inv *inventory.Inventory) (*vulndb.Result, error) {
	return f(ctx, inv)
}

func emptyMatcher(_ context.Context, _ *inventory.Inventory) (*vulndb.Result, error) {
	return &vulndb.Result{Vulnerabilities: map[string]*v1alpha1.Vulnerability{}}, nil
}

func TestDirectoryAndGitScanParity(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"requirements.txt": "requests==2.19.1\n", "app.py": "import requests\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-b", "main"}, {"add", "."}, {"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %s: %v", out, err)
		}
	}
	extractors := all.Extractors(all.Options{})
	engine := &Engine{Extractors: extractors, Matcher: matcherFunc(emptyMatcher)}
	local, err := engine.ScanDirectory(context.Background(), dir, v1alpha1.RepositoryInfo{Name: "fixture"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Scanner{WorkDir: t.TempDir(), Extractors: extractors, Matcher: matcherFunc(emptyMatcher), CloneURL: func(github.RepoRef) string { return dir }}
	cloned, err := s.Scan(context.Background(), "scan", v1alpha1.ScanSpec{RepositoryURL: "https://github.com/example/fixture", Ref: "main"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(local.Inventory.Components) == 0 || len(local.Code.Packages) == 0 {
		t.Fatalf("fixture not analysed: %+v", local)
	}
	if !reflect.DeepEqual(local.Inventory, cloned.Inventory) || !reflect.DeepEqual(local.Code, cloned.Code) || !reflect.DeepEqual(local.Match, cloned.Match) {
		t.Fatal("local and Git paths diverge")
	}
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err != nil {
		t.Fatalf("checkout changed: %v", err)
	}
	entries, err := os.ReadDir(s.WorkDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("clone not cleaned: %v %v", entries, err)
	}
}

func TestDirectoryErrorsAndDiagnostics(t *testing.T) {
	engine := &Engine{Extractors: all.Extractors(all.Options{}), Matcher: matcherFunc(emptyMatcher)}
	if _, err := engine.ScanDirectory(context.Background(), filepath.Join(t.TempDir(), "missing"), v1alpha1.RepositoryInfo{}, nil); err == nil {
		t.Fatal("missing path accepted")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := engine.ScanDirectory(context.Background(), dir, v1alpha1.RepositoryInfo{}, nil)
	if err != nil || r == nil || len(r.Match.Warnings) == 0 {
		t.Fatalf("lost extraction failure: %v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.ScanDirectory(ctx, dir, v1alpha1.RepositoryInfo{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	want := errors.New("provider offline")
	engine.Matcher = matcherFunc(func(context.Context, *inventory.Inventory) (*vulndb.Result, error) { return nil, want })
	if _, err := engine.ScanDirectory(context.Background(), dir, v1alpha1.RepositoryInfo{}, nil); !errors.Is(err, want) {
		t.Fatalf("matcher error lost: %v", err)
	}
}

package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactDirectoryLinksCannotOverwriteExternalFiles(t *testing.T) {
	root := realTempDir(t)
	victim := filepath.Join(root, "victim")
	if err := os.Mkdir(victim, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(victim, "report.json")
	if err := os.WriteFile(file, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "cassandra-results")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{link, filepath.Join(link, "nested")} {
		if err := writeArtifact(dir, "report.json", []byte("replace")); err == nil {
			t.Fatalf("accepted output-directory link: %s", dir)
		}
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "keep" {
		t.Fatalf("outside file changed: %s %v", data, err)
	}
}

func TestArtifactAtomicReplacementDoesNotFollowFileLinks(t *testing.T) {
	root := realTempDir(t)
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "reports")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(out, "report.json")); err != nil {
		t.Fatal(err)
	}
	if err := writeArtifact(out, "report.json", []byte("report")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(victim); err != nil || string(data) != "keep" {
		t.Fatalf("symlink target changed: %s %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(out, "report.json")); err != nil || string(data) != "report" {
		t.Fatalf("report missing: %s %v", data, err)
	}
	if err := writeArtifact(filepath.Join(root, "new", "nested"), "report.json", []byte("report")); err != nil {
		t.Fatal(err)
	}
}

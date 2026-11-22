package inventory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"strings"
)

// Extractor turns one manifest file into a Result. Implementations live in
// pkg/inventory/extractor/<ecosystem>, the same split osv-scalibr uses.
type Extractor interface {
	Name() string
	// FileRequired reports whether the file at the slash separated,
	// repository relative path is a manifest this extractor understands.
	FileRequired(p string) bool
	// Extract returns nil, nil when the file turns out to be irrelevant.
	Extract(ctx context.Context, in *Input) (*Result, error)
}

// Input gives an extractor access to the manifest and its siblings.
type Input struct {
	FS   fs.FS
	Path string
}

// Dir is the directory containing the manifest.
func (in *Input) Dir() string { return path.Dir(in.Path) }

// Read returns the manifest content.
func (in *Input) Read() ([]byte, error) { return readLimited(in.FS, in.Path) }

// Sibling returns the path of a file next to the manifest.
func (in *Input) Sibling(name string) string { return path.Join(in.Dir(), name) }

// Exists reports whether a repository relative file exists.
func (in *Input) Exists(p string) bool {
	fi, err := fs.Stat(in.FS, p)
	return err == nil && !fi.IsDir()
}

// ReadFile reads a repository relative file.
func (in *Input) ReadFile(p string) ([]byte, error) { return readLimited(in.FS, p) }

// MaxFileSize bounds how much of a manifest is read.
const MaxFileSize = 32 << 20

func readLimited(fsys fs.FS, p string) ([]byte, error) {
	fi, err := fs.Stat(fsys, p)
	if err != nil {
		return nil, err
	}
	if fi.Size() > MaxFileSize {
		return nil, fmt.Errorf("%s: file too large (%d bytes)", p, fi.Size())
	}
	return fs.ReadFile(fsys, p)
}

// SkipDirs are never descended into: vendored code, build output and
// installed dependencies would otherwise be reported as first party.
var SkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	"target": true, ".venv": true, "venv": true, "__pycache__": true, ".next": true,
	".nuxt": true, ".idea": true, ".vscode": true, "testdata": true, "bower_components": true,
	".gradle": true, ".terraform": true, "coverage": true,
}

// Extract walks fsys and runs every extractor on the files it requires.
// Extraction errors of single manifests are logged and skipped so that one
// malformed file does not fail the whole scan.
func Extract(ctx context.Context, fsys fs.FS, extractors []Extractor, log *slog.Logger) (*Inventory, error) {
	inv := &Inventory{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if p != "." && (SkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") && d.Name() != ".github") {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks may point outside the checkout
		}
		for _, e := range extractors {
			if !e.FileRequired(p) {
				continue
			}
			res, err := e.Extract(ctx, &Input{FS: fsys, Path: p})
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return err
				}
				log.Warn("[inventory] Extract failed", "extractor", e.Name(), "path", p, "err", err)
				continue
			}
			if res != nil && res.Project != nil {
				inv.Merge(res)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	inv.Sort()
	return inv, nil
}

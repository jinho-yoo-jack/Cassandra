package codegraph

import (
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
)

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

type goLang struct{}

func (goLang) name() string                   { return "go" }
func (goLang) ecosystem() inventory.Ecosystem { return inventory.Go }
func (goLang) matches(f string) bool {
	return strings.HasSuffix(f, ".go") && !strings.HasSuffix(f, "_test.go")
}

func (goLang) imports(file string, src []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.ImportsOnly)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(f.Imports))
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (goLang) resolve(r *resolver, proj *inventory.Project, _ string, spec string) (string, bool, bool) {
	if proj == nil {
		return "", false, false
	}
	if spec == proj.Name || strings.HasPrefix(spec, proj.Name+"/") {
		return path.Join(proj.Dir, strings.TrimPrefix(strings.TrimPrefix(spec, proj.Name), "/")), true, true
	}
	first, _, _ := strings.Cut(spec, "/")
	if !strings.Contains(first, ".") {
		id, ok := r.component(inventory.Go, "stdlib", proj)
		return id, false, ok
	}
	// The module is the longest prefix of the import path in the build list.
	for p := spec; p != "." && p != ""; p = path.Dir(p) {
		if id, ok := r.component(inventory.Go, p, proj); ok {
			return id, false, true
		}
		if !strings.Contains(p, "/") {
			break
		}
	}
	return "", false, false
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript
// ---------------------------------------------------------------------------

type jsLang struct{}

var jsExtensions = []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}

var jsImport = regexp.MustCompile(`(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"]([^'"\n]+)['"]`)

func (jsLang) name() string                   { return "javascript" }
func (jsLang) ecosystem() inventory.Ecosystem { return inventory.NPM }
func (jsLang) matches(f string) bool {
	if strings.HasSuffix(f, ".d.ts") || strings.Contains(f, ".min.") {
		return false
	}
	for _, e := range jsExtensions {
		if strings.HasSuffix(f, e) {
			return true
		}
	}
	return false
}

func (jsLang) imports(_ string, src []byte) []string {
	var out []string
	for _, m := range jsImport.FindAllSubmatch(src, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

func (jsLang) resolve(r *resolver, proj *inventory.Project, dir, spec string) (string, bool, bool) {
	switch {
	case strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../"):
		return path.Clean(path.Join(dir, spec)), true, true
	case strings.HasPrefix(spec, "@/") || strings.HasPrefix(spec, "~/"):
		// The conventional tsconfig "paths" alias for the source root.
		if proj == nil {
			return "", false, false
		}
		return path.Join(proj.Dir, "src", spec[2:]), true, true
	case strings.HasPrefix(spec, "node:"):
		return "", false, false
	}
	name := spec
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") && len(parts) >= 2 {
		name = parts[0] + "/" + parts[1]
	} else {
		name = parts[0]
	}
	id, ok := r.component(inventory.NPM, name, proj)
	return id, false, ok
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

type pyLang struct{}

var (
	pyImport     = regexp.MustCompile(`(?m)^\s*import\s+([\w.]+(?:\s*,\s*[\w.]+)*)`)
	pyFromImport = regexp.MustCompile(`(?m)^\s*from\s+(\.*[\w.]*)\s+import\b`)
)

// pyDistributions maps import names to the distributions that provide them
// when the two differ.
var pyDistributions = map[string]string{
	"yaml": "pyyaml", "PIL": "pillow", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
	"cv2": "opencv-python", "jwt": "pyjwt", "dateutil": "python-dateutil", "dotenv": "python-dotenv",
	"Crypto": "pycryptodome", "OpenSSL": "pyopenssl", "magic": "python-magic", "git": "gitpython",
	"google.protobuf": "protobuf", "attr": "attrs", "jose": "python-jose", "multipart": "python-multipart",
}

func (pyLang) name() string                   { return "python" }
func (pyLang) ecosystem() inventory.Ecosystem { return inventory.PyPI }
func (pyLang) matches(f string) bool          { return strings.HasSuffix(f, ".py") }

func (pyLang) imports(_ string, src []byte) []string {
	var out []string
	for _, m := range pyImport.FindAllSubmatch(src, -1) {
		for mod := range strings.SplitSeq(string(m[1]), ",") {
			out = append(out, strings.TrimSpace(mod))
		}
	}
	for _, m := range pyFromImport.FindAllSubmatch(src, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

func (pyLang) resolve(r *resolver, proj *inventory.Project, dir, spec string) (string, bool, bool) {
	if strings.HasPrefix(spec, ".") {
		rest := strings.TrimLeft(spec, ".")
		base := dir
		for range len(spec) - len(rest) - 1 {
			base = path.Dir(base)
		}
		return path.Join(base, strings.ReplaceAll(rest, ".", "/")), true, true
	}
	top, _, _ := strings.Cut(spec, ".")
	root := "."
	if proj != nil {
		root = proj.Dir
	}
	for _, base := range []string{root, path.Join(root, "src")} {
		if _, ok := r.pkgs[path.Join(base, top)]; ok {
			return path.Join(base, strings.ReplaceAll(spec, ".", "/")), true, true
		}
	}
	for _, cand := range []string{spec, top} {
		if d, ok := pyDistributions[cand]; ok {
			id, ok := r.component(inventory.PyPI, d, proj)
			return id, false, ok
		}
	}
	id, ok := r.component(inventory.PyPI, inventory.NormalizePyPI(top), proj)
	return id, false, ok
}

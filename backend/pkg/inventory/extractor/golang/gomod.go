// Package golang extracts Go modules from go.mod files.
package golang

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/sync/errgroup"

	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
)

// StdlibName is the OSV package name of the Go standard library.
const StdlibName = "stdlib"

// Extractor reads go.mod. go.mod only lists the build list, not who requires
// whom, so when a module proxy is configured the extractor fetches the
// go.mod of every module in the build list to recover the real graph.
type Extractor struct {
	// Proxy is a GOPROXY base URL. Empty disables graph resolution and
	// attaches every module directly to the project.
	Proxy  string
	Client *http.Client

	cache sync.Map // module@version -> []module.Version
}

// New returns an Extractor using the given module proxy.
func New(proxy string) *Extractor {
	return &Extractor{Proxy: strings.TrimSuffix(proxy, "/"), Client: &http.Client{Timeout: 15 * time.Second}}
}

func (e *Extractor) Name() string { return "go/gomod" }

func (e *Extractor) FileRequired(p string) bool { return path.Base(p) == "go.mod" }

func (e *Extractor) Extract(ctx context.Context, in *inventory.Input) (*inventory.Result, error) {
	data, err := in.Read()
	if err != nil {
		return nil, err
	}
	// Parse, not ParseLax: replace and toolchain directives only apply to
	// the main module and ParseLax drops them.
	f, err := modfile.Parse(in.Path, data, nil)
	if err != nil {
		return nil, err
	}
	if f.Module == nil {
		return nil, fmt.Errorf("%s: missing module directive", in.Path)
	}

	proj := &inventory.Project{
		ID: inventory.ProjectID(in.Path), Name: f.Module.Mod.Path, Dir: in.Dir(),
		Manifest: in.Path, Ecosystem: inventory.Go,
	}
	res := &inventory.Result{Project: proj}

	replaced := map[string]module.Version{}
	for _, r := range f.Replace {
		if r.New.Version == "" {
			replaced[r.Old.Path] = module.Version{} // local directory: not a third party module
			continue
		}
		replaced[r.Old.Path] = r.New
	}

	buildList := map[string]*inventory.Component{}
	direct := map[string]bool{}
	for _, req := range f.Require {
		mod := req.Mod
		if r, ok := replaced[mod.Path]; ok {
			if r.Path == "" {
				continue
			}
			mod = r
		}
		c := inventory.NewLibrary(inventory.Go, mod.Path, mod.Version, in.Path, !req.Indirect, false)
		buildList[req.Mod.Path] = c
		direct[req.Mod.Path] = !req.Indirect
		res.Components = append(res.Components, c)
	}

	if v := goVersion(f); v != "" {
		std := inventory.NewLibrary(inventory.Go, StdlibName, v, in.Path, true, false)
		res.Components = append(res.Components, std)
		res.Dependencies = append(res.Dependencies, inventory.Dependency{From: proj.ID, To: std.ID})
	}

	reached := map[string]bool{}
	if e.Proxy != "" {
		edges := e.moduleGraph(ctx, buildList)
		for from, tos := range edges {
			for _, to := range tos {
				res.Dependencies = append(res.Dependencies, inventory.Dependency{From: buildList[from].ID, To: buildList[to].ID})
				reached[to] = true
			}
		}
	}
	for p, c := range buildList {
		// Direct requirements, and anything the graph could not explain,
		// hang off the project so no module is orphaned.
		if direct[p] || !reached[p] {
			res.Dependencies = append(res.Dependencies, inventory.Dependency{From: proj.ID, To: c.ID})
		}
	}
	return res, nil
}

// goVersion returns the toolchain version used for stdlib matching: the
// toolchain directive when present, otherwise the go directive.
func goVersion(f *modfile.File) string {
	if f.Toolchain != nil {
		return strings.TrimPrefix(f.Toolchain.Name, "go")
	}
	if f.Go == nil {
		return ""
	}
	v := f.Go.Version
	if strings.Count(v, ".") == 1 {
		v += ".0"
	}
	return v
}

// moduleGraph returns, for each module in the build list, the other build
// list modules its go.mod requires.
func (e *Extractor) moduleGraph(ctx context.Context, buildList map[string]*inventory.Component) map[string][]string {
	var (
		mu    sync.Mutex
		edges = map[string][]string{}
	)
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(16)
	for p, c := range buildList {
		g.Go(func() error {
			reqs, err := e.requirements(ctx, module.Version{Path: c.Name, Version: c.Version})
			if err != nil {
				return nil // private or missing module: keep it attached to the project
			}
			var tos []string
			for _, r := range reqs {
				if _, ok := buildList[r.Path]; ok && r.Path != p {
					tos = append(tos, r.Path)
				}
			}
			mu.Lock()
			edges[p] = tos
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()
	return edges
}

func (e *Extractor) requirements(ctx context.Context, m module.Version) ([]module.Version, error) {
	key := m.String()
	if v, ok := e.cache.Load(key); ok {
		return v.([]module.Version), nil
	}
	escPath, err := module.EscapePath(m.Path)
	if err != nil {
		return nil, err
	}
	escVer, err := module.EscapeVersion(m.Version)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s/@v/%s.mod", e.Proxy, escPath, escVer), nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned %s for %s", resp.Status, key)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	f, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return nil, err
	}
	reqs := make([]module.Version, 0, len(f.Require))
	for _, r := range f.Require {
		reqs = append(reqs, r.Mod)
	}
	e.cache.Store(key, reqs)
	return reqs, nil
}

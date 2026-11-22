// Package scanner runs one scan: clone, extract the inventory (SBOM), build
// the code graph and match vulnerabilities.
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/codegraph"
	"github.com/jinho-yoo-jack/vulngraph/pkg/git"
	"github.com/jinho-yoo-jack/vulngraph/pkg/github"
	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
	"github.com/jinho-yoo-jack/vulngraph/pkg/report"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb"
)

// Scanner produces reports.
type Scanner struct {
	WorkDir     string
	GitHubToken string
	Extractors  []inventory.Extractor
	Matcher     *vulndb.Matcher
	Log         *slog.Logger
	// CloneURL overrides the clone URL, used by tests to scan local repos.
	CloneURL func(github.RepoRef) string
}

// Progress reports a human readable step.
type Progress func(message string)

// Scan clones the repository of spec and analyses it. The working copy is
// removed afterwards.
func (s *Scanner) Scan(ctx context.Context, name string, spec v1alpha1.ScanSpec, progress Progress) (*report.Report, error) {
	ref, err := github.ParseRepoURL(spec.RepositoryURL)
	if err != nil {
		return nil, err
	}
	gitRef := spec.Ref
	if gitRef == "" {
		gitRef = ref.Ref
	}
	cloneURL := ref.CloneURL()
	if s.CloneURL != nil {
		cloneURL = s.CloneURL(ref)
	}

	dir := filepath.Join(s.WorkDir, "scans", name)
	_ = os.RemoveAll(dir)
	defer os.RemoveAll(dir)

	progress(fmt.Sprintf("Cloning %s", ref.HTMLURL()))
	_, cloned, err := git.Clone(ctx, dir, git.CloneOptions{URL: cloneURL, Ref: gitRef, Depth: 1, Token: s.GitHubToken})
	if err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}

	progress("Extracting dependencies (SBOM)")
	fsys := os.DirFS(dir)
	inv, err := inventory.Extract(ctx, fsys, s.Extractors, s.Log)
	if err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}

	progress("Analysing source imports")
	code, err := codegraph.Build(ctx, fsys, inv, codegraph.DefaultOptions)
	if err != nil {
		return nil, fmt.Errorf("code graph: %w", err)
	}

	progress(fmt.Sprintf("Matching %d components against OSV and NVD", len(inv.Components)))
	match, err := s.Matcher.Match(ctx, inv)
	if err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}

	now := time.Now().UTC()
	branch := cloned.Branch
	if branch == "" {
		branch = gitRef
	}
	return &report.Report{
		Repository: v1alpha1.RepositoryInfo{
			Owner: ref.Owner, Name: ref.Name, URL: ref.HTMLURL(), Branch: branch, Commit: cloned.Commit,
		},
		Inventory: inv, Code: code, Match: match, GeneratedAt: now, EvaluatedAt: now,
	}, nil
}

// Reevaluate re-matches a stored report's inventory and returns the updated
// report and the advisories that were not in the previous result.
func (s *Scanner) Reevaluate(ctx context.Context, r *report.Report) (*report.Report, []string, error) {
	match, err := s.Matcher.Match(ctx, r.Inventory)
	if err != nil {
		return nil, nil, err
	}
	previous := map[string]bool{}
	for _, f := range r.Match.Findings {
		previous[f.ComponentID+"|"+f.VulnerabilityID] = true
	}
	var added []string
	for _, f := range match.Findings {
		if !previous[f.ComponentID+"|"+f.VulnerabilityID] {
			added = append(added, match.Vulnerabilities[f.VulnerabilityID].DisplayID())
		}
	}
	updated := *r
	updated.Match = match
	updated.EvaluatedAt = time.Now().UTC()
	return &updated, added, nil
}

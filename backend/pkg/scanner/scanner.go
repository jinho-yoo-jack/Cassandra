// Package scanner runs one scan: clone, extract the inventory (SBOM), build
// the code graph and match vulnerabilities.
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/git"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
)

// Scanner produces reports.
type Scanner struct {
	WorkDir     string
	GitHubToken string
	Extractors  []inventory.Extractor
	Matcher     Matcher
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

	if err := os.MkdirAll(s.WorkDir, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(s.WorkDir, "scan-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	notify(progress, fmt.Sprintf("Cloning %s", ref.HTMLURL()))
	_, cloned, err := git.Clone(ctx, dir, git.CloneOptions{URL: cloneURL, Ref: gitRef, Depth: 1, Token: s.GitHubToken})
	if err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}

	branch := cloned.Branch
	if branch == "" {
		branch = gitRef
	}
	engine := &Engine{Extractors: s.Extractors, Matcher: s.Matcher, Log: s.Log}
	return engine.ScanDirectory(ctx, dir, v1alpha1.RepositoryInfo{
		Owner: ref.Owner, Name: ref.Name, URL: ref.HTMLURL(), Branch: branch, Commit: cloned.Commit,
	}, progress)
}

// Reevaluate re-matches a stored report's inventory and returns the updated
// report and the advisories that were not in the previous result.
func (s *Scanner) Reevaluate(ctx context.Context, r *report.Report) (*report.Report, []string, error) {
	match, err := s.Matcher.Match(ctx, r.Inventory)
	if err != nil {
		return nil, nil, err
	}
	// Re-matching cannot repair an incomplete inventory without re-extraction.
	for _, warning := range r.Match.Warnings {
		if strings.HasPrefix(warning, "inventory:") {
			match.Warnings = append(match.Warnings, warning)
		}
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

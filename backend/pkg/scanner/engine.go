package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/codegraph"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
)

// Matcher is the analysis engine's only vulnerability lookup dependency.
// Neither source acquisition nor persistence belongs to this contract.
type Matcher interface {
	Match(context.Context, *inventory.Inventory) (*vulndb.Result, error)
}

// Engine analyses a filesystem without cloning, executing target code, opening
// a database, or starting controllers. Both server and CLI use this pipeline.
type Engine struct {
	Extractors []inventory.Extractor
	Matcher    Matcher
	Log        *slog.Logger
}

func notify(progress Progress, message string) {
	if progress != nil {
		progress(message)
	}
}

// ScanDirectory never removes or changes the caller's checkout. Root.FS also
// prevents extractor sibling reads from escaping through a symlink.
func (e *Engine) ScanDirectory(ctx context.Context, dir string, repo v1alpha1.RepositoryInfo, progress Progress) (*report.Report, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("scan directory: %w", err)
	}
	defer root.Close()
	return e.Analyze(ctx, root.FS(), repo, progress)
}

// Analyze performs extraction, code analysis and matching against the same
// filesystem. Warnings remain in the report so each adapter can apply policy.
func (e *Engine) Analyze(ctx context.Context, fsys fs.FS, repo v1alpha1.RepositoryInfo, progress Progress) (*report.Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.Matcher == nil {
		return nil, fmt.Errorf("scanner requires a matcher")
	}
	notify(progress, "Extracting dependencies (SBOM)")
	inv, warnings, err := inventory.ExtractWithDiagnostics(ctx, fsys, e.Extractors, e.Log)
	if err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}
	notify(progress, "Analysing source imports")
	code, err := codegraph.Build(ctx, fsys, inv, codegraph.DefaultOptions)
	if err != nil {
		return nil, fmt.Errorf("code graph: %w", err)
	}
	notify(progress, fmt.Sprintf("Matching %d components against OSV and NVD", len(inv.Components)))
	match, err := e.Matcher.Match(ctx, inv)
	if err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if match == nil {
		return nil, fmt.Errorf("matcher returned no result")
	}
	match.Warnings = append(warnings, match.Warnings...)
	now := time.Now().UTC()
	return &report.Report{Repository: repo, Inventory: inv, Code: code, Match: match, GeneratedAt: now, EvaluatedAt: now}, nil
}

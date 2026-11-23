// Package app is the headless CLI adapter. Analysis, encoding and CI policy
// remain independent packages shared with, or reusable outside, this command.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/bootstrap"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/output"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/sbom"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/scanner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/scanpolicy"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	path, outputDir, failOn string
	formats                 []string
	timeout                 time.Duration
	repository, commit, ref string
	sources                 bootstrap.ScanOptions
}

type exitError struct {
	code    int
	message string
}

func (e *exitError) Error() string { return e.message }

// Execute maps policy violations to 1 and operational/usage failures to 2.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd := NewCommand()
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		var policyError *exitError
		if errors.As(err, &policyError) {
			return policyError.code
		}
		return 2
	}
	return 0
}

func NewCommand() *cobra.Command {
	root := &cobra.Command{Use: "cassandra", Short: "Scan a checkout without a server or executing its code.", Version: sbom.ToolVersion, SilenceUsage: true, SilenceErrors: true}
	o := scanOptions{}
	scan := &cobra.Command{Use: "scan", Short: "Create reports and apply a vulnerability policy to a local directory.", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return o.run(cmd) }}
	f := scan.Flags()
	f.StringVar(&o.path, "path", ".", "Directory to analyse (never cloned, changed or executed).")
	f.StringVar(&o.outputDir, "output-dir", "cassandra-results", "Directory for report artifacts.")
	f.StringSliceVar(&o.formats, "format", output.Formats(), "Comma-separated output formats: json,markdown,cyclonedx,spdx,sarif.")
	f.StringVar(&o.failOn, "fail-on", "high", "Fail on low, medium, high, critical or none. Unknown severity also blocks enabled gates; incomplete scans always fail.")
	f.DurationVar(&o.timeout, "timeout", 5*time.Minute, "Total network and scan time budget.")
	f.StringVar(&o.repository, "repository", os.Getenv("GITHUB_REPOSITORY"), "Optional owner/repo metadata; does not select or clone the source.")
	f.StringVar(&o.commit, "commit", os.Getenv("GITHUB_SHA"), "Optional commit metadata for the checked-out tree.")
	f.StringVar(&o.ref, "ref", os.Getenv("GITHUB_REF_NAME"), "Optional branch/ref metadata.")
	f.StringVar(&o.sources.GoProxy, "go-proxy", "https://proxy.golang.org", "Go module proxy; empty disables graph expansion.")
	f.StringVar(&o.sources.OSVURL, "osv-url", "", "Override OSV API base URL.")
	f.StringVar(&o.sources.NVDURL, "nvd-url", "", "Override NVD CVE endpoint.")
	f.StringVar(&o.sources.KEVURL, "kev-url", "", "Override CISA KEV catalog URL.")
	f.StringVar(&o.sources.EPSSURL, "epss-url", "", "Override FIRST EPSS endpoint.")
	root.AddCommand(scan)
	return root
}

func (o scanOptions) run(cmd *cobra.Command) error {
	policy, err := scanpolicy.New(o.failOn)
	if err != nil {
		return err
	}
	if o.timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if len(o.formats) == 0 {
		return fmt.Errorf("at least one output format is required")
	}
	for _, format := range o.formats {
		if _, err := output.Filename(format); err != nil {
			return err
		}
	}
	dir, err := filepath.Abs(o.path)
	if err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("scan path is not a directory")
	}
	if o.outputDir == "" {
		return fmt.Errorf("output-dir must not be empty")
	}
	repo := v1alpha1.RepositoryInfo{Name: filepath.Base(dir), Commit: o.commit, Branch: o.ref}
	if o.repository != "" {
		ref, err := github.ParseRepoURL("https://github.com/" + o.repository)
		if err != nil {
			return fmt.Errorf("repository metadata: %w", err)
		}
		repo.Owner, repo.Name, repo.URL = ref.Owner, ref.Name, ref.HTMLURL()
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()
	o.sources.NVDAPIKey = os.Getenv("NVD_API_KEY")
	runtime := bootstrap.NewScan(o.sources)
	if err := runtime.Prepare(ctx); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
	engine := scanner.Engine{Extractors: runtime.Extractors, Matcher: runtime.Matcher(vulndb.NewMemoryCache(), log), Log: log}
	r, err := engine.ScanDirectory(ctx, dir, repo, func(message string) { log.Info(message) })
	if err != nil {
		return err
	}
	// Persist diagnostic artifacts before returning a nonzero policy result.
	for _, format := range o.formats {
		data, err := output.Encode(r, format)
		if err != nil {
			return err
		}
		name, _ := output.Filename(format)
		if err := writeArtifact(o.outputDir, name, data); err != nil {
			return err
		}
	}
	decision := policy.Evaluate(r)
	summary := r.Summary()
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%d components, %d vulnerabilities. Reports: %s\n", summary.Components, summary.Vulnerabilities, o.outputDir); err != nil {
		return err
	}
	if decision.ExitCode != 0 {
		return &exitError{decision.ExitCode, decision.Message}
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), decision.Message)
	return err
}

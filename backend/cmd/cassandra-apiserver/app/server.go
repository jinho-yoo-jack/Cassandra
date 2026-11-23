// Package app wires the command line to the API server, like
// k8s.io/kubernetes/cmd/kube-apiserver/app.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	bolt "go.etcd.io/bbolt"

	"github.com/jinho-yoo-jack/Cassandra/backend/cmd/cassandra-apiserver/app/options"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apiserver"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/bootstrap"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/deploy"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/git"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/runner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/server"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage/boltstore"
)

// NewAPIServerCommand creates the root command.
func NewAPIServerCommand() *cobra.Command {
	s := options.NewServerRunOptions()
	cmd := &cobra.Command{
		Use:   "cassandra-apiserver",
		Short: "Scan GitHub repositories into SBOM graphs, track vulnerabilities and drive their remediation.",
		Long: `cassandra-apiserver clones a GitHub repository, builds an SBOM and a code/dependency
graph, matches every component against OSV and NVD (enriched with CISA KEV and EPSS),
keeps re-evaluating stored scans as feeds change, and runs remediations from branch to
pull request (and image build, runtime test and deploy for server images).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			completed, err := s.Complete()
			if err != nil {
				return err
			}
			if errs := completed.Validate(); len(errs) != 0 {
				return errors.Join(errs...)
			}
			return Run(cmd.Context(), completed)
		},
	}

	fss := s.Flags()
	for _, name := range fss.Order {
		cmd.Flags().AddFlagSet(fss.FlagSets[name])
	}
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		printSections(cmd.OutOrStderr(), cmd.UseLine(), fss)
		return nil
	})
	cmd.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n", cmd.Long)
		printSections(cmd.OutOrStdout(), cmd.UseLine(), fss)
	})
	return cmd
}

func printSections(w io.Writer, use string, fss options.NamedFlagSets) {
	fmt.Fprintf(w, "Usage:\n  %s\n", use)
	for _, name := range fss.Order {
		fmt.Fprintf(w, "\n%s flags:\n\n%s", strings.ToUpper(name[:1])+name[1:], fss.FlagSets[name].FlagUsages())
	}
}

// Run runs the server until ctx is cancelled.
func Run(ctx context.Context, opts options.CompletedOptions) error {
	log := newLogger(opts.Logging)
	slog.SetDefault(log)

	if err := os.MkdirAll(opts.Storage.DataDir, 0o700); err != nil {
		return err
	}
	db, err := boltstore.Open(filepath.Join(opts.Storage.DataDir, "cassandra.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	config := CreateServerConfig(opts, db, log)
	srv, err := config.Complete().New()
	if err != nil {
		return err
	}
	return srv.GenericAPIServer.PrepareRun().Run(ctx)
}

// CreateServerConfig turns options into the server configuration.
func CreateServerConfig(opts options.CompletedOptions, db *bolt.DB, log *slog.Logger) *apiserver.Config {
	scan := bootstrap.NewScan(bootstrap.ScanOptions{NVDAPIKey: opts.Feeds.NVDAPIKey, GoProxy: opts.Feeds.GoProxy})
	var r runner.Runner = runner.NewDocker()
	if opts.Remediation.Runner == "local" {
		r = runner.Local{}
	}
	docker := &runner.DockerCLI{}
	return &apiserver.Config{
		GenericConfig: &server.Config{
			BindAddress: opts.Serving.BindAddress, Port: opts.Serving.Port,
			ShutdownTimeout: opts.Serving.ShutdownTimeout, StaticDir: opts.Serving.StaticDir, Logger: log,
		},
		ExtraConfig: apiserver.ExtraConfig{
			DB: db, DataDir: opts.Storage.DataDir,
			OSV: scan.OSV, NVD: scan.NVD, KEV: scan.KEV, EPSS: scan.EPSS,
			Extractors: scan.Extractors,
			Runner:     r, Docker: docker, Toolchains: opts.Toolchains,
			GitHub:   github.NewClient(opts.GitHub.Token),
			Author:   git.Signature{Name: opts.Remediation.AuthorName, Email: opts.Remediation.AuthorEmail},
			Deployer: &deploy.Deployer{Docker: docker, Registry: opts.Remediation.Registry, Kubectl: opts.Remediation.Kubectl},
			Feeds: apiserver.FeedConfig{
				Enabled: opts.Feeds.Enabled, OSVInterval: opts.Feeds.OSVInterval, NVDInterval: opts.Feeds.NVDInterval,
				KEVInterval: opts.Feeds.KEVInterval, OSVEcosystems: opts.Feeds.OSVEcosystems,
				WebhookSecret: opts.GitHub.WebhookSecret,
			},
			ConcurrentScanSyncs:        opts.Controllers.ConcurrentScanSyncs,
			ConcurrentRemediationSyncs: opts.Controllers.ConcurrentRemediationSyncs,
		},
	}
}

func newLogger(o *options.LoggingOptions) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(o.Level))
	hopts := &slog.HandlerOptions{Level: level}
	if o.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, hopts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, hopts))
}

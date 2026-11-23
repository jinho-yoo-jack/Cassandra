// Package apiserver assembles cassandra-apiserver from the generic server,
// the registries, the controllers and the feed syncer, following the
// Config → Complete → New pattern of k8s.io/sample-apiserver.
package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/bootstrap"
	remediationcontroller "github.com/jinho-yoo-jack/Cassandra/backend/pkg/controller/remediation"
	scancontroller "github.com/jinho-yoo-jack/Cassandra/backend/pkg/controller/scan"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/deploy"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/endpoints"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/feeds"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/fixer"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/git"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	feedregistry "github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/feed"
	remediationregistry "github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/remediation"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/rest"
	scanregistry "github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/scan"
	vulnregistry "github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/vulnerability"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/reportstore"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/runner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/scanner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/server"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage/boltstore"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/epss"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/kev"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/workspace"
)

// FeedConfig configures the feed syncer.
type FeedConfig struct {
	Enabled       bool
	OSVInterval   time.Duration
	NVDInterval   time.Duration
	KEVInterval   time.Duration
	OSVEcosystems []string
	WebhookSecret string
}

// ExtraConfig holds cassandra specific configuration.
type ExtraConfig struct {
	DB      *bolt.DB
	DataDir string

	OSV  *osv.Client
	NVD  *nvd.Client
	KEV  *kev.Catalog
	EPSS *epss.Client

	Extractors []inventory.Extractor
	Runner     runner.Runner
	Docker     *runner.DockerCLI
	Toolchains fixer.Toolchains
	GitHub     *github.Client
	Author     git.Signature
	Deployer   *deploy.Deployer
	Feeds      FeedConfig

	ConcurrentScanSyncs        int
	ConcurrentRemediationSyncs int

	// CloneURL overrides clone URLs; tests point it at local repositories.
	CloneURL func(github.RepoRef) string
}

// Config is the full server configuration.
type Config struct {
	GenericConfig *server.Config
	ExtraConfig   ExtraConfig
}

type completedConfig struct {
	GenericConfig server.CompletedConfig
	ExtraConfig   *ExtraConfig
}

// CompletedConfig can only be obtained through Complete.
type CompletedConfig struct {
	*completedConfig
}

// Complete fills in defaults.
func (cfg *Config) Complete() CompletedConfig {
	if cfg.ExtraConfig.ConcurrentScanSyncs <= 0 {
		cfg.ExtraConfig.ConcurrentScanSyncs = 2
	}
	if cfg.ExtraConfig.ConcurrentRemediationSyncs <= 0 {
		cfg.ExtraConfig.ConcurrentRemediationSyncs = 2
	}
	return CompletedConfig{&completedConfig{GenericConfig: cfg.GenericConfig.Complete(), ExtraConfig: &cfg.ExtraConfig}}
}

// CassandraServer is the assembled server.
type CassandraServer struct {
	GenericAPIServer      *server.GenericAPIServer
	ScanController        *scancontroller.Controller
	RemediationController *remediationcontroller.Controller
	Syncer                *feeds.Syncer
}

// New builds the server.
func (c CompletedConfig) New() (*CassandraServer, error) {
	x := c.ExtraConfig
	log := c.GenericConfig.Logger

	genericServer, err := c.GenericConfig.New()
	if err != nil {
		return nil, err
	}

	scans, err := boltstore.New(x.DB, v1alpha1.ResourceScans, func() *v1alpha1.Scan { return &v1alpha1.Scan{} })
	if err != nil {
		return nil, err
	}
	remediations, err := boltstore.New(x.DB, v1alpha1.ResourceRemediations, func() *v1alpha1.Remediation { return &v1alpha1.Remediation{} })
	if err != nil {
		return nil, err
	}
	feedStore, err := boltstore.New(x.DB, v1alpha1.ResourceFeeds, func() *v1alpha1.Feed { return &v1alpha1.Feed{} })
	if err != nil {
		return nil, err
	}
	reportBlobs, err := boltstore.NewBlobs(x.DB, "reports")
	if err != nil {
		return nil, err
	}
	vulnBlobs, err := boltstore.NewBlobs(x.DB, "advisories")
	if err != nil {
		return nil, err
	}
	reports := reportstore.New(reportBlobs)
	cache := vulndb.NewCache(vulnBlobs)
	scanRuntime := &bootstrap.ScanRuntime{OSV: x.OSV, NVD: x.NVD, KEV: x.KEV, EPSS: x.EPSS, Extractors: x.Extractors}
	matcher := scanRuntime.Matcher(cache, log)
	layout := workspace.Layout{Root: x.DataDir}

	sc := &scanner.Scanner{
		WorkDir: layout.Scans(), GitHubToken: x.GitHub.Token, Extractors: x.Extractors,
		Matcher: matcher, Log: log, CloneURL: x.CloneURL,
	}
	scanController := scancontroller.NewController(scans, reports, sc, log)
	remediationController := remediationcontroller.NewController(remediationcontroller.Config{
		Remediations: remediations, Reports: reports, Matcher: matcher, Extractors: x.Extractors,
		Layout: layout, Runner: x.Runner, Docker: x.Docker, Toolchains: x.Toolchains,
		GitHub: x.GitHub, Author: x.Author, Deployer: x.Deployer, Log: log, CloneURL: x.CloneURL,
	})

	syncer := &feeds.Syncer{Feeds: feedStore, Sink: scanController, Log: log}
	if x.Feeds.Enabled {
		syncer.Sources = []feeds.Source{
			&feeds.OSVSource{Client: x.OSV, Cache: cache, Ecosystems: x.Feeds.OSVEcosystems, Every: x.Feeds.OSVInterval, BatchSize: 200},
			&feeds.NVDSource{Client: x.NVD, Cache: cache, Every: x.Feeds.NVDInterval},
			&feeds.KEVSource{Catalog: x.KEV, Every: x.Feeds.KEVInterval},
		}
	}

	scanREST, graphREST, sbomREST := scanregistry.NewREST(scans, reports)
	remStorage := remediationregistry.NewStorage(remediations, scans, reports, layout)
	genericServer.InstallAPIGroup(&endpoints.APIGroupVersion{
		Group: v1alpha1.GroupName, Version: v1alpha1.Version,
		Storage: map[string]rest.Storage{
			"scans":                 scanREST,
			"scans/graph":           graphREST,
			"scans/sbom":            sbomREST,
			"remediations":          remStorage.Remediation,
			"remediations/approval": remStorage.Approval,
			"remediations/docs":     remStorage.Docs,
			"remediations/diff":     remStorage.Diff,
			"vulnerabilities":       vulnregistry.NewREST(matcher),
			"feeds":                 feedregistry.NewREST(feedStore),
		},
	})

	if x.Feeds.Enabled && x.Feeds.WebhookSecret != "" {
		syncer.Sources = append(syncer.Sources, feeds.WebhookSource{})
		genericServer.Mux.Handle("POST /webhooks/github", &feeds.GitHubWebhook{
			Secret: []byte(x.Feeds.WebhookSecret), OSV: x.OSV, Cache: cache, Syncer: syncer, Log: log,
		})
	}

	genericServer.AddReadyzChecks(server.HealthCheck{Name: "storage", Check: func(*http.Request) error {
		return x.DB.View(func(*bolt.Tx) error { return nil })
	}})
	hooks := []struct {
		name string
		run  func(ctx context.Context)
	}{
		{"start-scan-controller", func(ctx context.Context) { scanController.Run(ctx, x.ConcurrentScanSyncs) }},
		{"start-remediation-controller", func(ctx context.Context) { remediationController.Run(ctx, x.ConcurrentRemediationSyncs) }},
		{"start-feed-syncer", syncer.Run},
		{"load-kev-catalog", func(ctx context.Context) {
			if _, _, err := x.KEV.Refresh(ctx); err != nil {
				log.Warn("[apiserver] Initial KEV load failed; retried by the feed syncer", "err", err)
			}
		}},
	}
	for _, h := range hooks {
		run := h.run
		if err := genericServer.AddPostStartHook(h.name, func(hookCtx server.PostStartHookContext) error {
			hookCtx.Go(func() { run(hookCtx) })
			return nil
		}); err != nil {
			return nil, fmt.Errorf("add post-start hook: %w", err)
		}
	}

	log.Info("[apiserver] Configured", "dataDir", x.DataDir, "feeds", x.Feeds.Enabled,
		"webhook", x.Feeds.WebhookSecret != "", "githubToken", x.GitHub.Token != "")
	return &CassandraServer{
		GenericAPIServer: genericServer, ScanController: scanController,
		RemediationController: remediationController, Syncer: syncer,
	}, nil
}

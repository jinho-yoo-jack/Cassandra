// Package options contains the flags of cassandra-apiserver, grouped into
// named flag sets like kube-apiserver's ServerRunOptions.
package options

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/fixer"
)

// ServingOptions configure the HTTP server.
type ServingOptions struct {
	BindAddress     string
	Port            int
	StaticDir       string
	ShutdownTimeout time.Duration
}

// StorageOptions configure persistence.
type StorageOptions struct {
	DataDir string
}

// FeedOptions configure vulnerability sources.
type FeedOptions struct {
	Enabled       bool
	OSVInterval   time.Duration
	NVDInterval   time.Duration
	KEVInterval   time.Duration
	OSVEcosystems []string
	NVDAPIKey     string
	GoProxy       string
}

// GitHubOptions configure GitHub access.
type GitHubOptions struct {
	Token         string
	WebhookSecret string
}

// RemediationOptions configure the remediation pipeline.
type RemediationOptions struct {
	Runner          string
	ToolchainImages map[string]string
	Registry        string
	Kubectl         string
	AuthorName      string
	AuthorEmail     string
}

// ControllerOptions configure controller concurrency.
type ControllerOptions struct {
	ConcurrentScanSyncs        int
	ConcurrentRemediationSyncs int
}

// LoggingOptions configure slog.
type LoggingOptions struct {
	Level  string
	Format string
}

// ServerRunOptions are every flag of the server.
type ServerRunOptions struct {
	Serving     *ServingOptions
	Storage     *StorageOptions
	Feeds       *FeedOptions
	GitHub      *GitHubOptions
	Remediation *RemediationOptions
	Controllers *ControllerOptions
	Logging     *LoggingOptions
}

// NewServerRunOptions returns options with defaults.
func NewServerRunOptions() *ServerRunOptions {
	return &ServerRunOptions{
		Serving: &ServingOptions{BindAddress: "127.0.0.1", Port: 8080, ShutdownTimeout: 30 * time.Second},
		Storage: &StorageOptions{},
		Feeds: &FeedOptions{
			Enabled: true, OSVInterval: 10 * time.Minute, NVDInterval: 2 * time.Hour, KEVInterval: 24 * time.Hour,
			OSVEcosystems: []string{"Go", "npm", "PyPI", "Maven", "crates.io", "RubyGems", "Packagist"},
			GoProxy:       "https://proxy.golang.org",
		},
		GitHub: &GitHubOptions{},
		Remediation: &RemediationOptions{
			Runner: "docker", ToolchainImages: map[string]string{}, Kubectl: "kubectl",
			AuthorName: "cassandra-bot", AuthorEmail: "cassandra-bot@users.noreply.github.com",
		},
		Controllers: &ControllerOptions{ConcurrentScanSyncs: 2, ConcurrentRemediationSyncs: 2},
		Logging:     &LoggingOptions{Level: "info", Format: "text"},
	}
}

// NamedFlagSets keeps flag sets in display order.
type NamedFlagSets struct {
	Order    []string
	FlagSets map[string]*pflag.FlagSet
}

// FlagSet returns (creating if needed) the named flag set.
func (n *NamedFlagSets) FlagSet(name string) *pflag.FlagSet {
	if n.FlagSets == nil {
		n.FlagSets = map[string]*pflag.FlagSet{}
	}
	if _, ok := n.FlagSets[name]; !ok {
		n.FlagSets[name] = pflag.NewFlagSet(name, pflag.ExitOnError)
		n.Order = append(n.Order, name)
	}
	return n.FlagSets[name]
}

// Flags returns the flags grouped by subsystem.
func (s *ServerRunOptions) Flags() NamedFlagSets {
	var fss NamedFlagSets

	fs := fss.FlagSet("serving")
	fs.StringVar(&s.Serving.BindAddress, "bind-address", s.Serving.BindAddress, "Address to listen on. The server runs builds and pushes branches, so keep it on loopback unless it sits behind authentication.")
	fs.IntVar(&s.Serving.Port, "port", s.Serving.Port, "Port to listen on.")
	fs.StringVar(&s.Serving.StaticDir, "static-dir", s.Serving.StaticDir, "Directory of the built web UI to serve at /. Empty serves the API only.")
	fs.DurationVar(&s.Serving.ShutdownTimeout, "shutdown-timeout", s.Serving.ShutdownTimeout, "Grace period for in-flight requests on shutdown.")

	fs = fss.FlagSet("storage")
	fs.StringVar(&s.Storage.DataDir, "data-dir", s.Storage.DataDir, "Directory for the database and working copies. Defaults to ~/.cassandra.")

	fs = fss.FlagSet("feeds")
	fs.BoolVar(&s.Feeds.Enabled, "feeds", s.Feeds.Enabled, "Continuously sync OSV, NVD and CISA KEV and re-evaluate stored scans.")
	fs.DurationVar(&s.Feeds.OSVInterval, "osv-sync-interval", s.Feeds.OSVInterval, "How often to follow OSV modified_id.csv.")
	fs.DurationVar(&s.Feeds.NVDInterval, "nvd-sync-interval", s.Feeds.NVDInterval, "How often to poll NVD. NVD asks for no more than every two hours.")
	fs.DurationVar(&s.Feeds.KEVInterval, "kev-sync-interval", s.Feeds.KEVInterval, "How often to refresh the CISA KEV catalog.")
	fs.StringSliceVar(&s.Feeds.OSVEcosystems, "osv-ecosystems", s.Feeds.OSVEcosystems, "OSV ecosystems to follow.")
	fs.StringVar(&s.Feeds.NVDAPIKey, "nvd-api-key", s.Feeds.NVDAPIKey, "NVD API key (raises the rate limit from 5 to 50 requests per 30s). Defaults to $NVD_API_KEY.")
	fs.StringVar(&s.Feeds.GoProxy, "go-proxy", s.Feeds.GoProxy, "Go module proxy used to resolve the Go module graph. Empty disables it.")

	fs = fss.FlagSet("github")
	fs.StringVar(&s.GitHub.Token, "github-token", s.GitHub.Token, "Token for cloning private repositories, pushing fix branches and opening pull requests. Defaults to $GITHUB_TOKEN.")
	fs.StringVar(&s.GitHub.WebhookSecret, "github-webhook-secret", s.GitHub.WebhookSecret, "Secret of the GitHub App webhook receiving security_advisory events at /webhooks/github. Empty disables the endpoint. Defaults to $GITHUB_WEBHOOK_SECRET.")

	fs = fss.FlagSet("remediation")
	fs.StringVar(&s.Remediation.Runner, "runner", s.Remediation.Runner, "Where builds and tests of scanned repositories run: docker (isolated) or local (no isolation).")
	fs.StringToStringVar(&s.Remediation.ToolchainImages, "toolchain-image", s.Remediation.ToolchainImages, "Override toolchain images, e.g. go=golang:1.27,node=node:24. Keys: "+strings.Join(toolchainKeys(), ", ")+".")
	fs.StringVar(&s.Remediation.Registry, "registry", s.Remediation.Registry, "Registry prefix remediated images are pushed to before deployment, e.g. ghcr.io/acme.")
	fs.StringVar(&s.Remediation.Kubectl, "kubectl", s.Remediation.Kubectl, "kubectl binary used to deploy remediated images.")
	fs.StringVar(&s.Remediation.AuthorName, "commit-author-name", s.Remediation.AuthorName, "Author name of remediation commits.")
	fs.StringVar(&s.Remediation.AuthorEmail, "commit-author-email", s.Remediation.AuthorEmail, "Author email of remediation commits.")

	fs = fss.FlagSet("controllers")
	fs.IntVar(&s.Controllers.ConcurrentScanSyncs, "concurrent-scan-syncs", s.Controllers.ConcurrentScanSyncs, "Scans processed concurrently.")
	fs.IntVar(&s.Controllers.ConcurrentRemediationSyncs, "concurrent-remediation-syncs", s.Controllers.ConcurrentRemediationSyncs, "Remediations processed concurrently.")

	fs = fss.FlagSet("logging")
	fs.StringVar(&s.Logging.Level, "log-level", s.Logging.Level, "debug, info, warn or error.")
	fs.StringVar(&s.Logging.Format, "log-format", s.Logging.Format, "text or json.")
	return fss
}

func toolchainKeys() []string {
	keys := make([]string, 0, len(fixer.DefaultToolchains))
	for k := range fixer.DefaultToolchains {
		keys = append(keys, k)
	}
	return keys
}

type completedOptions struct {
	*ServerRunOptions
	Toolchains fixer.Toolchains
}

// CompletedOptions can only be obtained through Complete.
type CompletedOptions struct {
	*completedOptions
}

// Complete fills in values derived from the environment.
func (s *ServerRunOptions) Complete() (CompletedOptions, error) {
	if s.Storage.DataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return CompletedOptions{}, err
		}
		s.Storage.DataDir = filepath.Join(home, ".cassandra")
	}
	if s.GitHub.Token == "" {
		s.GitHub.Token = os.Getenv("GITHUB_TOKEN")
	}
	if s.GitHub.WebhookSecret == "" {
		s.GitHub.WebhookSecret = os.Getenv("GITHUB_WEBHOOK_SECRET")
	}
	if s.Feeds.NVDAPIKey == "" {
		s.Feeds.NVDAPIKey = os.Getenv("NVD_API_KEY")
	}
	toolchains := fixer.Toolchains{}
	for k, v := range fixer.DefaultToolchains {
		toolchains[k] = v
	}
	for k, v := range s.Remediation.ToolchainImages {
		toolchains[k] = v
	}
	return CompletedOptions{&completedOptions{ServerRunOptions: s, Toolchains: toolchains}}, nil
}

// Validate checks the completed options.
func (o CompletedOptions) Validate() []error {
	var errs []error
	if o.Serving.Port < 1 || o.Serving.Port > 65535 {
		errs = append(errs, fmt.Errorf("--port %d must be between 1 and 65535", o.Serving.Port))
	}
	switch o.Remediation.Runner {
	case "docker":
		if _, err := exec.LookPath("docker"); err != nil {
			errs = append(errs, errors.New("--runner=docker requires the docker CLI; install Docker or pass --runner=local to run builds without isolation"))
		}
	case "local":
	default:
		errs = append(errs, fmt.Errorf("--runner must be docker or local, got %q", o.Remediation.Runner))
	}
	if o.Feeds.Enabled {
		for name, d := range map[string]time.Duration{"--osv-sync-interval": o.Feeds.OSVInterval, "--nvd-sync-interval": o.Feeds.NVDInterval, "--kev-sync-interval": o.Feeds.KEVInterval} {
			if d < time.Minute {
				errs = append(errs, fmt.Errorf("%s must be at least 1m", name))
			}
		}
	}
	for k := range o.Remediation.ToolchainImages {
		if _, ok := fixer.DefaultToolchains[k]; !ok {
			errs = append(errs, fmt.Errorf("--toolchain-image: unknown key %q", k))
		}
	}
	if o.Controllers.ConcurrentScanSyncs < 1 || o.Controllers.ConcurrentRemediationSyncs < 1 {
		errs = append(errs, errors.New("controller concurrency must be at least 1"))
	}
	if o.Serving.StaticDir != "" {
		if _, err := os.Stat(filepath.Join(o.Serving.StaticDir, "index.html")); err != nil {
			errs = append(errs, fmt.Errorf("--static-dir: %w", err))
		}
	}
	switch o.Logging.Format {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("--log-format must be text or json"))
	}
	return errs
}

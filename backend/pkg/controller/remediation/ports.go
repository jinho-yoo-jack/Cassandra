package remediation

import (
	"context"
	"log/slog"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/fixer"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/git"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/runner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/watch"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/workspace"
)

// RemediationStore is the state and watch access required by the controller.
// Creating and deleting remediations remain registry responsibilities.
type RemediationStore interface {
	Get(context.Context, string) (*v1alpha1.Remediation, error)
	List(context.Context) ([]*v1alpha1.Remediation, string, error)
	GuaranteedUpdate(context.Context, string, storage.UpdateFunc[*v1alpha1.Remediation]) (*v1alpha1.Remediation, error)
	Watch(context.Context, bool) (watch.Interface, error)
}

// ReportReader only reads the scanned input; step execution cannot store reports.
type ReportReader interface {
	Get(string) (*report.Report, error)
}

// ComponentMatcher rechecks only the fixed component, not an entire scan.
type ComponentMatcher interface {
	MatchComponents(context.Context, *inventory.Inventory, []string) (*vulndb.Result, error)
}

// DockerExecutor runs the container commands required by remediation.
type DockerExecutor interface {
	Exec(context.Context, ...string) (string, error)
}

// ImageDeployer publishes an image to a configured target.
type ImageDeployer interface {
	Enabled(*v1alpha1.DeployTarget) bool
	Deploy(context.Context, string, *v1alpha1.DeployTarget) (string, string, error)
}

// PullRequestCreator is independent of Git transport credentials.
type PullRequestCreator interface {
	CreatePullRequest(context.Context, github.RepoRef, github.NewPullRequest) (*github.PullRequest, error)
}

// workingCopy is the subset of Git operations used by commands.
type workingCopy interface {
	ResetHard(context.Context, string) error
	ChangedFiles(context.Context, string) ([]string, error)
	CommitAll(context.Context, string, git.Signature) (string, error)
	CommitPaths(context.Context, string, git.Signature, ...string) (string, error)
	Push(context.Context, string) error
}

// Config retains the server's composition entrypoint. Executor overrides the
// default commands, so controller tests need no report, Git or container setup.
type Config struct {
	Remediations RemediationStore
	Reports      ReportReader
	Matcher      ComponentMatcher
	Extractors   []inventory.Extractor
	Layout       workspace.Layout
	Runner       runner.Runner
	Docker       DockerExecutor
	Toolchains   fixer.Toolchains
	GitHub       *github.Client
	Author       git.Signature
	Deployer     ImageDeployer
	Log          *slog.Logger
	// CloneURL overrides clone URLs (tests).
	CloneURL func(github.RepoRef) string
	Executor StepExecutor
}

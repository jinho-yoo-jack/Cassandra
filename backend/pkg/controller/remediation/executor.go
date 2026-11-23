package remediation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/fixer"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/git"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/runner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/workspace"
)

// StepExecutor executes one side-effecting step. It does not persist state or
// decide which step runs next. Review is exclusively a controller transition.
type StepExecutor interface {
	Execute(context.Context, v1alpha1.StepName, *v1alpha1.Remediation) StepResult
}

// StepResult carries the outcome and a copy of produced status. The controller
// persists only output fields, never Phase, Steps or reviewer identity.
type StepResult struct {
	State   v1alpha1.StepState
	Message string
	Log     string
	// Fatal stops the pipeline; failed tests remain nonfatal for human review.
	Fatal  bool
	Status *v1alpha1.RemediationStatus
}

func succeeded(msg string) StepResult {
	return StepResult{State: v1alpha1.StepSucceeded, Message: msg}
}
func skipped(msg string) StepResult { return StepResult{State: v1alpha1.StepSkipped, Message: msg} }
func fatal(err error, log string) StepResult {
	return StepResult{State: v1alpha1.StepFailed, Message: err.Error(), Log: log, Fatal: true}
}

// command binds an existing step to its implementation without another pipeline
// engine. The controller owns ordering, retry, approval and recovery.
type command func(context.Context, *stepContext) StepResult

// stepExecutor owns the execution collaborators only: it has no state store or
// queue and cannot approve or advance a remediation itself.
type stepExecutor struct {
	Reports    ReportReader
	Matcher    ComponentMatcher
	Extractors []inventory.Extractor
	Layout     workspace.Layout
	Runner     runner.Runner
	Docker     DockerExecutor
	Toolchains fixer.Toolchains
	GitHub     PullRequestCreator
	Author     git.Signature
	Deployer   ImageDeployer
	Log        *slog.Logger
	CloneURL   func(github.RepoRef) string
	gitToken   string
	commands   map[v1alpha1.StepName]command
}

func newStepExecutor(cfg Config) *stepExecutor {
	e := &stepExecutor{
		Reports: cfg.Reports, Matcher: cfg.Matcher, Extractors: cfg.Extractors,
		Layout: cfg.Layout, Runner: cfg.Runner, Docker: cfg.Docker,
		Toolchains: cfg.Toolchains, GitHub: cfg.GitHub, Author: cfg.Author,
		Deployer: cfg.Deployer, Log: cfg.Log, CloneURL: cfg.CloneURL,
	}
	if cfg.GitHub != nil {
		e.gitToken = cfg.GitHub.Token
	}
	e.commands = map[v1alpha1.StepName]command{
		v1alpha1.StepCreateBranch:       e.createBranch,
		v1alpha1.StepApplyFix:           e.applyFix,
		v1alpha1.StepWriteTestScenarios: e.writeTestScenarios,
		v1alpha1.StepBuildImage:         e.buildImage,
		v1alpha1.StepTest:               e.test,
		v1alpha1.StepDeploy:             e.deploy,
		v1alpha1.StepPullRequest:        e.pullRequest,
	}
	return e
}

func (e *stepExecutor) Execute(ctx context.Context, name v1alpha1.StepName, rem *v1alpha1.Remediation) (out StepResult) {
	var sc *stepContext
	defer func() {
		if r := recover(); r != nil {
			out = fatal(fmt.Errorf("step panicked: %v", r), "")
		}
		if sc != nil {
			out.Status = sc.status
		}
	}()
	cmd, ok := e.commands[name]
	if !ok {
		return fatal(fmt.Errorf("unknown step %s", name), "")
	}
	var err error
	sc, err = e.loadContext(ctx, rem)
	if err != nil {
		return fatal(err, "")
	}
	return cmd(ctx, sc)
}

// isManual reports whether a fixer could not handle the case automatically.
func isManual(err error) bool { return errors.Is(err, fixer.ErrManual) }

// Package remediation is the remediation controller. Each Remediation is a
// small state machine whose steps are recorded in status.steps, so a
// restarted server resumes where it stopped and the UI can render progress
// from the watch stream alone.
package remediation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/deploy"
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

// pipelines lists the steps of each remediation kind in order.
var pipelines = map[v1alpha1.RemediationKind][]v1alpha1.StepName{
	v1alpha1.RemediationDependency: {
		v1alpha1.StepCreateBranch, v1alpha1.StepApplyFix, v1alpha1.StepWriteTestScenarios,
		v1alpha1.StepTest, v1alpha1.StepReview, v1alpha1.StepPullRequest,
	},
	v1alpha1.RemediationImage: {
		v1alpha1.StepCreateBranch, v1alpha1.StepApplyFix, v1alpha1.StepWriteTestScenarios,
		v1alpha1.StepBuildImage, v1alpha1.StepTest, v1alpha1.StepReview, v1alpha1.StepDeploy, v1alpha1.StepPullRequest,
	},
}

// Config holds the controller's collaborators.
type Config struct {
	Remediations storage.Interface[*v1alpha1.Remediation]
	Reports      *report.Store
	Matcher      *vulndb.Matcher
	Extractors   []inventory.Extractor
	Layout       workspace.Layout
	Runner       runner.Runner
	Docker       *runner.DockerCLI
	Toolchains   fixer.Toolchains
	GitHub       *github.Client
	Author       git.Signature
	Deployer     *deploy.Deployer
	Log          *slog.Logger
	// CloneURL overrides clone URLs (tests).
	CloneURL func(github.RepoRef) string
}

// Controller reconciles Remediations.
type Controller struct {
	Config
	queue workqueue.TypedRateLimitingInterface[string]
}

// NewController returns a controller.
func NewController(cfg Config) *Controller {
	return &Controller{
		Config: cfg,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "remediation"},
		),
	}
}

// Run starts workers and blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context, workers int) {
	defer c.queue.ShutDown()
	c.Log.Info("[remediation-controller] Starting", "workers", workers)
	if err := c.recoverInterrupted(ctx); err != nil {
		c.Log.Error("[remediation-controller] Recover failed", "err", err)
	}
	go c.watchLoop(ctx)
	for range workers {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}
	<-ctx.Done()
	c.Log.Info("[remediation-controller] Stopping")
}

// recoverInterrupted resets steps left Running by a previous process so
// they are executed again. Every step is written to be re-runnable.
func (c *Controller) recoverInterrupted(ctx context.Context) error {
	items, _, err := c.Remediations.List(ctx)
	if err != nil {
		return err
	}
	for _, r := range items {
		if r.Status.Phase.IsTerminal() {
			continue
		}
		_, err := c.Remediations.GuaranteedUpdate(ctx, r.Name, func(cur *v1alpha1.Remediation) (*v1alpha1.Remediation, error) {
			for i := range cur.Status.Steps {
				if cur.Status.Steps[i].State == v1alpha1.StepRunning {
					cur.Status.Steps[i].State, cur.Status.Steps[i].Message = v1alpha1.StepPending, "Restarted after interruption"
				}
			}
			return cur, nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) watchLoop(ctx context.Context) {
	for ctx.Err() == nil {
		w, err := c.Remediations.Watch(ctx, true)
		if err != nil {
			c.Log.Error("[remediation-controller] Watch failed", "err", err)
			time.Sleep(time.Second)
			continue
		}
		c.consume(ctx, w)
	}
}

func (c *Controller) consume(ctx context.Context, w watch.Interface) {
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.ResultChan():
			if !ok {
				return
			}
			r := ev.Object.(*v1alpha1.Remediation)
			if ev.Type == watch.Deleted || r.Status.Phase.IsTerminal() || r.Status.Phase == v1alpha1.RemediationAwaitingReview {
				continue
			}
			c.queue.Add(r.Name)
		}
	}
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextItem(ctx) {
	}
}

func (c *Controller) processNextItem(ctx context.Context) bool {
	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(key)
	if err := c.sync(ctx, key); err != nil && ctx.Err() == nil {
		if c.queue.NumRequeues(key) < 5 {
			c.Log.Warn("[remediation-controller] Sync failed, requeueing", "remediation", key, "err", err)
			c.queue.AddRateLimited(key)
			return true
		}
		c.Log.Error("[remediation-controller] Dropping remediation", "remediation", key, "err", err)
	}
	c.queue.Forget(key)
	return true
}

// stepOutcome is the result of one step.
type stepOutcome struct {
	state   v1alpha1.StepState
	message string
	log     string
	// fatal stops the pipeline; non-fatal failures (failed tests) continue
	// to the review so a human decides.
	fatal bool
}

func succeeded(msg string) stepOutcome {
	return stepOutcome{state: v1alpha1.StepSucceeded, message: msg}
}
func skipped(msg string) stepOutcome { return stepOutcome{state: v1alpha1.StepSkipped, message: msg} }
func fatal(err error, log string) stepOutcome {
	return stepOutcome{state: v1alpha1.StepFailed, message: err.Error(), log: log, fatal: true}
}

// sync advances one remediation until it waits for review or finishes.
func (c *Controller) sync(ctx context.Context, name string) error {
	for {
		rem, err := c.Remediations.Get(ctx, name)
		if storage.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if rem.Status.Phase.IsTerminal() || rem.Status.Phase == v1alpha1.RemediationAwaitingReview {
			return nil
		}
		if len(rem.Status.Steps) == 0 {
			if err := c.update(ctx, name, func(s *v1alpha1.RemediationStatus) {
				for _, n := range pipelines[s.Kind] {
					s.Steps = append(s.Steps, v1alpha1.RemediationStep{Name: n, State: v1alpha1.StepPending})
				}
				s.Phase, s.Message = v1alpha1.RemediationRunning, "Started"
			}); err != nil {
				return err
			}
			continue
		}

		step := nextStep(&rem.Status)
		if step == nil {
			return c.update(ctx, name, func(s *v1alpha1.RemediationStatus) {
				s.Phase = v1alpha1.RemediationCompleted
				if s.PullRequestURL != "" {
					s.Message = "Pull request created: " + s.PullRequestURL
				} else {
					s.Message = "Completed"
				}
			})
		}
		if step.Name == v1alpha1.StepReview {
			// Approval moves the phase to Approved and completes this step
			// through the approval subresource; until then, wait.
			return c.update(ctx, name, func(s *v1alpha1.RemediationStatus) {
				s.Phase, s.Message = v1alpha1.RemediationAwaitingReview, "Waiting for review"
				s.Step(v1alpha1.StepReview).State = v1alpha1.StepWaiting
			})
		}

		sc, err := c.loadContext(ctx, rem)
		if err != nil {
			return c.finish(ctx, name, step.Name, fatal(err, ""))
		}
		now := time.Now().UTC()
		if err := c.update(ctx, name, func(s *v1alpha1.RemediationStatus) {
			st := s.Step(step.Name)
			st.State, st.StartTime, st.CompletionTime, st.Message, st.Log = v1alpha1.StepRunning, &now, nil, "", ""
			s.Message = string(step.Name)
		}); err != nil {
			return err
		}
		c.Log.Info("[remediation-controller] Step started", "remediation", name, "step", step.Name)
		out := c.runStep(ctx, step.Name, sc)
		if ctx.Err() != nil {
			return ctx.Err() // shutting down; recoverInterrupted re-runs the step
		}
		if err := c.finishWithStatus(ctx, name, step.Name, out, sc.status); err != nil {
			return err
		}
		if out.fatal {
			return nil
		}
	}
}

func nextStep(s *v1alpha1.RemediationStatus) *v1alpha1.RemediationStep {
	for i := range s.Steps {
		switch s.Steps[i].State {
		case v1alpha1.StepPending, v1alpha1.StepRunning, v1alpha1.StepWaiting:
			return &s.Steps[i]
		}
	}
	return nil
}

func (c *Controller) runStep(ctx context.Context, name v1alpha1.StepName, sc *stepContext) (out stepOutcome) {
	defer func() {
		if r := recover(); r != nil {
			out = fatal(fmt.Errorf("step panicked: %v", r), "")
		}
	}()
	switch name {
	case v1alpha1.StepCreateBranch:
		return c.createBranch(ctx, sc)
	case v1alpha1.StepApplyFix:
		return c.applyFix(ctx, sc)
	case v1alpha1.StepWriteTestScenarios:
		return c.writeTestScenarios(ctx, sc)
	case v1alpha1.StepBuildImage:
		return c.buildImage(ctx, sc)
	case v1alpha1.StepTest:
		return c.test(ctx, sc)
	case v1alpha1.StepDeploy:
		return c.deploy(ctx, sc)
	case v1alpha1.StepPullRequest:
		return c.pullRequest(ctx, sc)
	}
	return fatal(fmt.Errorf("unknown step %s", name), "")
}

func (c *Controller) update(ctx context.Context, name string, mutate func(*v1alpha1.RemediationStatus)) error {
	_, err := c.Remediations.GuaranteedUpdate(ctx, name, func(cur *v1alpha1.Remediation) (*v1alpha1.Remediation, error) {
		mutate(&cur.Status)
		return cur, nil
	})
	return err
}

// finish records a step outcome without other status changes.
func (c *Controller) finish(ctx context.Context, name string, step v1alpha1.StepName, out stepOutcome) error {
	return c.finishWithStatus(ctx, name, step, out, nil)
}

// finishWithStatus records a step outcome and the status fields the step
// produced (branch, docs, results...).
func (c *Controller) finishWithStatus(ctx context.Context, name string, step v1alpha1.StepName, out stepOutcome, produced *v1alpha1.RemediationStatus) error {
	return c.update(ctx, name, func(s *v1alpha1.RemediationStatus) {
		if produced != nil {
			s.Branch, s.Commit, s.ToVersion, s.Docs = produced.Branch, produced.Commit, produced.ToVersion, produced.Docs
			s.TestResults, s.Image, s.PullRequestURL = produced.TestResults, produced.Image, produced.PullRequestURL
			s.Conditions = produced.Conditions
		}
		now := time.Now().UTC()
		st := s.Step(step)
		st.State, st.Message, st.Log, st.CompletionTime = out.state, out.message, runner.Tail(out.log), &now
		if out.fatal {
			s.Phase, s.Message = v1alpha1.RemediationFailed, fmt.Sprintf("%s failed: %s", step, out.message)
			for i := range s.Steps {
				if s.Steps[i].State == v1alpha1.StepPending {
					s.Steps[i].State = v1alpha1.StepSkipped
				}
			}
		}
	})
}

// isManual reports whether a fixer could not handle the case automatically.
func isManual(err error) bool { return errors.Is(err, fixer.ErrManual) }

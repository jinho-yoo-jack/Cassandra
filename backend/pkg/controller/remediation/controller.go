// Package remediation is the remediation controller. Each Remediation is a
// small state machine whose steps are recorded in status.steps, so a
// restarted server resumes where it stopped and the UI can render progress
// from the watch stream alone.
package remediation

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/runner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/watch"
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

// Controller reconciles Remediations.
type Controller struct {
	remediations RemediationStore
	executor     StepExecutor
	log          *slog.Logger
	queue        workqueue.TypedRateLimitingInterface[string]
}

// NewController returns a controller.
func NewController(cfg Config) *Controller {
	executor := cfg.Executor
	if executor == nil {
		executor = newStepExecutor(cfg)
	}
	return &Controller{
		remediations: cfg.Remediations,
		executor:     executor,
		log:          cfg.Log,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "remediation"},
		),
	}
}

// Run starts workers and blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context, workers int) {
	defer c.queue.ShutDown()
	c.log.Info("[remediation-controller] Starting", "workers", workers)
	if err := c.recoverInterrupted(ctx); err != nil {
		c.log.Error("[remediation-controller] Recover failed", "err", err)
	}
	go c.watchLoop(ctx)
	for range workers {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}
	<-ctx.Done()
	c.log.Info("[remediation-controller] Stopping")
}

// recoverInterrupted resets steps left Running by a previous process so
// they are executed again. Every step is written to be re-runnable.
func (c *Controller) recoverInterrupted(ctx context.Context) error {
	items, _, err := c.remediations.List(ctx)
	if err != nil {
		return err
	}
	for _, r := range items {
		if r.Status.Phase.IsTerminal() {
			continue
		}
		_, err := c.remediations.GuaranteedUpdate(ctx, r.Name, func(cur *v1alpha1.Remediation) (*v1alpha1.Remediation, error) {
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
		w, err := c.remediations.Watch(ctx, true)
		if err != nil {
			c.log.Error("[remediation-controller] Watch failed", "err", err)
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
			c.log.Warn("[remediation-controller] Sync failed, requeueing", "remediation", key, "err", err)
			c.queue.AddRateLimited(key)
			return true
		}
		c.log.Error("[remediation-controller] Dropping remediation", "remediation", key, "err", err)
	}
	c.queue.Forget(key)
	return true
}

// sync advances one remediation until it waits for review or finishes.
func (c *Controller) sync(ctx context.Context, name string) error {
	for {
		rem, err := c.remediations.Get(ctx, name)
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

		now := time.Now().UTC()
		if err := c.update(ctx, name, func(s *v1alpha1.RemediationStatus) {
			st := s.Step(step.Name)
			st.State, st.StartTime, st.CompletionTime, st.Message, st.Log = v1alpha1.StepRunning, &now, nil, "", ""
			s.Message = string(step.Name)
		}); err != nil {
			return err
		}
		c.log.Info("[remediation-controller] Step started", "remediation", name, "step", step.Name)
		out := c.executor.Execute(ctx, step.Name, rem)
		if ctx.Err() != nil {
			return ctx.Err() // shutting down; recoverInterrupted re-runs the step
		}
		if err := c.finishWithStatus(ctx, name, step.Name, out, out.Status); err != nil {
			return err
		}
		if out.Fatal {
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

func (c *Controller) update(ctx context.Context, name string, mutate func(*v1alpha1.RemediationStatus)) error {
	_, err := c.remediations.GuaranteedUpdate(ctx, name, func(cur *v1alpha1.Remediation) (*v1alpha1.Remediation, error) {
		mutate(&cur.Status)
		return cur, nil
	})
	return err
}

// finishWithStatus records a step outcome and the status fields the step
// produced (branch, docs, results...).
func (c *Controller) finishWithStatus(ctx context.Context, name string, step v1alpha1.StepName, out StepResult, produced *v1alpha1.RemediationStatus) error {
	return c.update(ctx, name, func(s *v1alpha1.RemediationStatus) {
		if produced != nil {
			s.Branch, s.Commit, s.ToVersion, s.Docs = produced.Branch, produced.Commit, produced.ToVersion, produced.Docs
			s.TestResults, s.Image, s.PullRequestURL = produced.TestResults, produced.Image, produced.PullRequestURL
			s.Conditions = produced.Conditions
		}
		now := time.Now().UTC()
		st := s.Step(step)
		st.State, st.Message, st.Log, st.CompletionTime = out.State, out.Message, runner.Tail(out.Log), &now
		if out.Fatal {
			s.Phase, s.Message = v1alpha1.RemediationFailed, fmt.Sprintf("%s failed: %s", step, out.Message)
			for i := range s.Steps {
				if s.Steps[i].State == v1alpha1.StepPending {
					s.Steps[i].State = v1alpha1.StepSkipped
				}
			}
		}
	})
}

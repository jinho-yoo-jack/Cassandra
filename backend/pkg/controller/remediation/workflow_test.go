package remediation

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	registry "github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/remediation"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage/boltstore"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/workspace"
)

type executorFunc func(context.Context, v1alpha1.StepName, *v1alpha1.Remediation) StepResult

func (f executorFunc) Execute(ctx context.Context, name v1alpha1.StepName, rem *v1alpha1.Remediation) StepResult {
	return f(ctx, name, rem)
}

func injectedController(t *testing.T, store *boltstore.Store[*v1alpha1.Remediation], executor StepExecutor) *Controller {
	t.Helper()
	c := NewController(Config{
		Remediations: store, Executor: executor,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	t.Cleanup(c.queue.ShutDown)
	return c
}

func TestInjectedExecutorFailurePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   v1alpha1.RemediationKind
		failed v1alpha1.StepName
		fatal  bool
	}{
		{"fatal fix stops", v1alpha1.RemediationDependency, v1alpha1.StepApplyFix, true},
		{"failed tests require review", v1alpha1.RemediationDependency, v1alpha1.StepTest, false},
		{"failed image build requires review", v1alpha1.RemediationImage, v1alpha1.StepBuildImage, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := remediationStore(t)
			putRemediation(t, store, v1alpha1.RemediationPending)
			if _, err := store.GuaranteedUpdate(context.Background(), "fix", func(r *v1alpha1.Remediation) (*v1alpha1.Remediation, error) {
				r.Status.Kind = tc.kind
				return r, nil
			}); err != nil {
				t.Fatal(err)
			}
			var calls []v1alpha1.StepName
			c := injectedController(t, store, executorFunc(func(_ context.Context, name v1alpha1.StepName, _ *v1alpha1.Remediation) StepResult {
				calls = append(calls, name)
				if name == tc.failed {
					return StepResult{State: v1alpha1.StepFailed, Message: "deliberate failure", Log: "failure detail", Fatal: tc.fatal}
				}
				return succeeded("ok")
			}))
			if err := c.sync(context.Background(), "fix"); err != nil {
				t.Fatal(err)
			}
			got := getRemediation(t, store).Status
			step := got.Step(tc.failed)
			if step.State != v1alpha1.StepFailed || step.Log != "failure detail" || step.CompletionTime == nil {
				t.Fatalf("failed step not recorded: %+v", step)
			}
			if tc.fatal {
				want := pipelines[tc.kind][:slices.Index(pipelines[tc.kind], tc.failed)+1]
				if got.Phase != v1alpha1.RemediationFailed || !reflect.DeepEqual(calls, want) {
					t.Fatalf("fatal did not stop: status=%+v calls=%v", got, calls)
				}
				for _, step := range got.Steps[len(want):] {
					if step.State != v1alpha1.StepSkipped {
						t.Errorf("remaining step not skipped: %+v", step)
					}
				}
			} else {
				if got.Phase != v1alpha1.RemediationAwaitingReview || got.Step(v1alpha1.StepReview).State != v1alpha1.StepWaiting || !slices.Contains(calls, v1alpha1.StepTest) {
					t.Fatalf("nonfatal did not reach review: status=%+v calls=%v", got, calls)
				}
				if slices.Contains(calls, v1alpha1.StepDeploy) || slices.Contains(calls, v1alpha1.StepPullRequest) {
					t.Fatalf("side effects before approval: %v", calls)
				}
			}
		})
	}
}

func TestCancelledExecutionResumesOnlyInterruptedStep(t *testing.T) {
	store := remediationStore(t)
	putRemediation(t, store, v1alpha1.RemediationRunning,
		v1alpha1.RemediationStep{Name: v1alpha1.StepCreateBranch, State: v1alpha1.StepSucceeded},
		v1alpha1.RemediationStep{Name: v1alpha1.StepApplyFix, State: v1alpha1.StepPending},
		v1alpha1.RemediationStep{Name: v1alpha1.StepReview, State: v1alpha1.StepPending},
		v1alpha1.RemediationStep{Name: v1alpha1.StepPullRequest, State: v1alpha1.StepPending})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls []v1alpha1.StepName
	c := injectedController(t, store, executorFunc(func(_ context.Context, name v1alpha1.StepName, _ *v1alpha1.Remediation) StepResult {
		calls = append(calls, name)
		cancel()
		return StepResult{State: v1alpha1.StepSucceeded, Status: &v1alpha1.RemediationStatus{Branch: "must-not-persist"}}
	}))
	if err := c.sync(ctx, "fix"); !errors.Is(err, context.Canceled) {
		t.Fatalf("sync = %v, want cancellation", err)
	}
	got := getRemediation(t, store).Status
	if got.Phase != v1alpha1.RemediationRunning || got.Branch != "" || got.Step(v1alpha1.StepApplyFix).State != v1alpha1.StepRunning || got.Step(v1alpha1.StepApplyFix).CompletionTime != nil {
		t.Fatalf("cancelled result was persisted: %+v", got)
	}
	if !reflect.DeepEqual(calls, []v1alpha1.StepName{v1alpha1.StepApplyFix}) {
		t.Fatalf("calls during cancellation = %v", calls)
	}
	// A new controller reads the persisted state, not the old executor's memory.
	var resumed []v1alpha1.StepName
	restarted := injectedController(t, store, executorFunc(func(_ context.Context, name v1alpha1.StepName, _ *v1alpha1.Remediation) StepResult {
		resumed = append(resumed, name)
		return succeeded("retried")
	}))
	if err := restarted.recoverInterrupted(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := restarted.sync(context.Background(), "fix"); err != nil {
		t.Fatal(err)
	}
	got = getRemediation(t, store).Status
	if !reflect.DeepEqual(resumed, []v1alpha1.StepName{v1alpha1.StepApplyFix}) || got.Phase != v1alpha1.RemediationAwaitingReview || got.Step(v1alpha1.StepApplyFix).State != v1alpha1.StepSucceeded {
		t.Fatalf("restart = %+v, calls = %v", got, resumed)
	}
}

func TestInjectedExecutorWaitsForApprovalBeforePullRequest(t *testing.T) {
	store := remediationStore(t)
	putRemediation(t, store, v1alpha1.RemediationPending)
	var calls []v1alpha1.StepName
	c := injectedController(t, store, executorFunc(func(ctx context.Context, name v1alpha1.StepName, rem *v1alpha1.Remediation) StepResult {
		calls = append(calls, name)
		persisted := getRemediation(t, store)
		if step := persisted.Status.Step(name); step.State != v1alpha1.StepRunning || step.StartTime == nil || step.CompletionTime != nil {
			t.Fatalf("must persist Running before execution: %+v", step)
		}
		status := rem.Status
		status.Branch = "feature/fix"
		status.ToVersion = "2.0.0"
		if name == v1alpha1.StepPullRequest {
			if rem.Status.Reviewer != "alice" || rem.Status.Phase != v1alpha1.RemediationApproved {
				t.Fatalf("PR without persisted approval: %+v", rem.Status)
			}
			status.PullRequestURL = "https://example.test/pull/7"
		}
		return StepResult{State: v1alpha1.StepSucceeded, Message: "executed", Status: &status}
	}))
	if err := c.sync(context.Background(), "fix"); err != nil {
		t.Fatal(err)
	}
	want := []v1alpha1.StepName{v1alpha1.StepCreateBranch, v1alpha1.StepApplyFix, v1alpha1.StepWriteTestScenarios, v1alpha1.StepTest}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("pre-approval calls = %v, want %v", calls, want)
	}
	waiting := getRemediation(t, store).Status
	if waiting.Phase != v1alpha1.RemediationAwaitingReview || waiting.Branch != "feature/fix" || waiting.ToVersion != "2.0.0" || waiting.Step(v1alpha1.StepReview).State != v1alpha1.StepWaiting {
		t.Fatalf("waiting status = %+v", waiting)
	}
	for _, name := range want {
		if step := waiting.Step(name); step.State != v1alpha1.StepSucceeded || step.CompletionTime == nil {
			t.Errorf("step result not recorded: %+v", step)
		}
	}
	if err := c.sync(context.Background(), "fix"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("execution while awaiting approval: %v", calls)
	}
	approval := registry.NewStorage(store, nil, nil, workspace.Layout{}).Approval
	if _, err := approval.Create(context.Background(), "fix", &v1alpha1.RemediationApproval{Reviewer: "alice", Approved: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.sync(context.Background(), "fix"); err != nil {
		t.Fatal(err)
	}
	want = append(want, v1alpha1.StepPullRequest)
	got := getRemediation(t, store).Status
	if !reflect.DeepEqual(calls, want) || got.Phase != v1alpha1.RemediationCompleted || got.PullRequestURL != "https://example.test/pull/7" || got.Reviewer != "alice" {
		t.Fatalf("completion = %+v, calls = %v", got, calls)
	}
	if err := c.sync(context.Background(), "fix"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("completed pipeline executed twice: %v", calls)
	}
}

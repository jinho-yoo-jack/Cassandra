package remediation

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	registry "github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/remediation"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage/boltstore"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/workspace"
)

func remediationStore(t *testing.T) *boltstore.Store[*v1alpha1.Remediation] {
	t.Helper()
	db, err := boltstore.Open(filepath.Join(t.TempDir(), "remediations.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := boltstore.New(db, v1alpha1.ResourceRemediations, func() *v1alpha1.Remediation { return &v1alpha1.Remediation{} })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Shutdown)
	return store
}

func testController(t *testing.T, store *boltstore.Store[*v1alpha1.Remediation]) *Controller {
	t.Helper()
	c := NewController(Config{Remediations: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	t.Cleanup(c.queue.ShutDown)
	return c
}

func putRemediation(t *testing.T, store *boltstore.Store[*v1alpha1.Remediation], phase v1alpha1.RemediationPhase, steps ...v1alpha1.RemediationStep) *v1alpha1.Remediation {
	t.Helper()
	r, err := store.Create(context.Background(), &v1alpha1.Remediation{
		ObjectMeta: v1alpha1.ObjectMeta{Name: "fix"},
		Status:     v1alpha1.RemediationStatus{Kind: v1alpha1.RemediationDependency, Phase: phase, Steps: steps},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func getRemediation(t *testing.T, store *boltstore.Store[*v1alpha1.Remediation]) *v1alpha1.Remediation {
	t.Helper()
	r, err := store.Get(context.Background(), "fix")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReviewGateAndDenial(t *testing.T) {
	store := remediationStore(t)
	c := testController(t, store)
	putRemediation(t, store, v1alpha1.RemediationRunning,
		v1alpha1.RemediationStep{Name: v1alpha1.StepReview, State: v1alpha1.StepPending},
		v1alpha1.RemediationStep{Name: v1alpha1.StepPullRequest, State: v1alpha1.StepPending})
	// No report, runner or GitHub is configured: review must be state-only.
	if err := c.sync(context.Background(), "fix"); err != nil {
		t.Fatal(err)
	}
	waiting := getRemediation(t, store)
	if waiting.Status.Phase != v1alpha1.RemediationAwaitingReview || waiting.Status.Step(v1alpha1.StepReview).State != v1alpha1.StepWaiting {
		t.Fatalf("review did not wait: %+v", waiting.Status)
	}
	if err := c.sync(context.Background(), "fix"); err != nil {
		t.Fatal(err)
	}
	if got := getRemediation(t, store); !reflect.DeepEqual(got.Status, waiting.Status) {
		t.Fatalf("waiting changed without a decision: %+v", got.Status)
	}
	approval := registry.NewStorage(store, nil, nil, workspace.Layout{}).Approval
	if _, err := approval.Create(context.Background(), "fix", &v1alpha1.RemediationApproval{Reviewer: "alice", Approved: false, Comment: "do not push"}); err != nil {
		t.Fatal(err)
	}
	if err := c.sync(context.Background(), "fix"); err != nil {
		t.Fatal(err)
	}
	got := getRemediation(t, store)
	if got.Status.Phase != v1alpha1.RemediationDenied || got.Status.Step(v1alpha1.StepPullRequest).State != v1alpha1.StepPending {
		t.Fatalf("denial must stop before PR: %+v", got.Status)
	}
}

func TestFinishStepOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		out   StepResult
		phase v1alpha1.RemediationPhase
		next  v1alpha1.StepState
	}{
		{"success", succeeded("ok"), v1alpha1.RemediationRunning, v1alpha1.StepPending},
		{"nonfatal test failure", StepResult{State: v1alpha1.StepFailed, Message: "failed tests"}, v1alpha1.RemediationRunning, v1alpha1.StepPending},
		{"fatal failure", fatal(errors.New("cannot fix"), "details"), v1alpha1.RemediationFailed, v1alpha1.StepSkipped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := remediationStore(t)
			c := testController(t, store)
			putRemediation(t, store, v1alpha1.RemediationRunning,
				v1alpha1.RemediationStep{Name: v1alpha1.StepTest, State: v1alpha1.StepRunning},
				v1alpha1.RemediationStep{Name: v1alpha1.StepReview, State: v1alpha1.StepPending},
				v1alpha1.RemediationStep{Name: v1alpha1.StepPullRequest, State: v1alpha1.StepPending})
			produced := &v1alpha1.RemediationStatus{Branch: "feature/fix", ToVersion: "2.0", Phase: v1alpha1.RemediationCompleted, Reviewer: "not a reviewer"}
			if err := c.finishWithStatus(context.Background(), "fix", v1alpha1.StepTest, tc.out, produced); err != nil {
				t.Fatal(err)
			}
			got := getRemediation(t, store).Status
			step := got.Step(v1alpha1.StepTest)
			if got.Phase != tc.phase || step.State != tc.out.State || step.Message != tc.out.Message || step.CompletionTime == nil {
				t.Fatalf("outcome not persisted: %+v", got)
			}
			if got.Step(v1alpha1.StepReview).State != tc.next || got.Step(v1alpha1.StepPullRequest).State != tc.next {
				t.Fatalf("remaining steps = %+v", got.Steps)
			}
			if got.Branch != produced.Branch || got.ToVersion != produced.ToVersion || got.Reviewer != "" {
				t.Fatalf("produced fields must not overwrite approval/state: %+v", got)
			}
			if tc.out.Fatal && !strings.Contains(got.Message, "Test failed: cannot fix") {
				t.Fatalf("fatal message = %q", got.Message)
			}
		})
	}
}

func TestRecoverInterruptedPreservesCompletedAndReview(t *testing.T) {
	for _, phase := range []v1alpha1.RemediationPhase{v1alpha1.RemediationRunning, v1alpha1.RemediationAwaitingReview, v1alpha1.RemediationDenied, v1alpha1.RemediationCompleted, v1alpha1.RemediationFailed} {
		t.Run(string(phase), func(t *testing.T) {
			store := remediationStore(t)
			c := testController(t, store)
			before := putRemediation(t, store, phase,
				v1alpha1.RemediationStep{Name: v1alpha1.StepCreateBranch, State: v1alpha1.StepSucceeded},
				v1alpha1.RemediationStep{Name: v1alpha1.StepTest, State: v1alpha1.StepRunning},
				v1alpha1.RemediationStep{Name: v1alpha1.StepReview, State: v1alpha1.StepWaiting})
			if err := c.recoverInterrupted(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := getRemediation(t, store)
			if phase.IsTerminal() {
				if !reflect.DeepEqual(before, got) {
					t.Fatalf("terminal state changed: %+v", got.Status)
				}
				return
			}
			if got.Status.Phase != phase || got.Status.Step(v1alpha1.StepCreateBranch).State != v1alpha1.StepSucceeded || got.Status.Step(v1alpha1.StepReview).State != v1alpha1.StepWaiting {
				t.Fatalf("recovery changed completed/review state: %+v", got.Status)
			}
			if st := got.Status.Step(v1alpha1.StepTest); st.State != v1alpha1.StepPending || st.Message != "Restarted after interruption" {
				t.Fatalf("interrupted step = %+v", st)
			}
		})
	}
}

func TestDeployRequiresPassingTestsAndImage(t *testing.T) {
	c := &stepExecutor{} // Missing deployer must never be reached by a refused deploy.
	for _, status := range []v1alpha1.RemediationStatus{
		{Image: "candidate:1"},
		{Image: "candidate:1", Conditions: []v1alpha1.Condition{{Type: v1alpha1.RemediationConditionTestsPassed, Status: v1alpha1.ConditionFalse}}},
		{Conditions: []v1alpha1.Condition{{Type: v1alpha1.RemediationConditionTestsPassed, Status: v1alpha1.ConditionTrue}}},
	} {
		out := c.deploy(context.Background(), &stepContext{status: &status})
		if out.State != v1alpha1.StepSkipped || out.Fatal {
			t.Fatalf("unsafe deploy was not skipped: %+v", out)
		}
	}
}

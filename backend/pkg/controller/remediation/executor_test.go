package remediation

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/git"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/runner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
)

type reportReaderFunc func(string) (*report.Report, error)

func (f reportReaderFunc) Get(name string) (*report.Report, error) { return f(name) }

type matcherFunc func(context.Context, *inventory.Inventory, []string) (*vulndb.Result, error)

func (f matcherFunc) MatchComponents(ctx context.Context, inv *inventory.Inventory, ids []string) (*vulndb.Result, error) {
	return f(ctx, inv, ids)
}

type dockerFunc func(context.Context, ...string) (string, error)

func (f dockerFunc) Exec(ctx context.Context, args ...string) (string, error) { return f(ctx, args...) }

type pullRequestFunc func(context.Context, github.RepoRef, github.NewPullRequest) (*github.PullRequest, error)

func (f pullRequestFunc) CreatePullRequest(ctx context.Context, ref github.RepoRef, pr github.NewPullRequest) (*github.PullRequest, error) {
	return f(ctx, ref, pr)
}

func executorFixture() (*v1alpha1.Remediation, *report.Report) {
	comp := inventory.NewLibrary(inventory.PyPI, "django", "3.2.0", "requirements.txt", true, false)
	vuln := &v1alpha1.Vulnerability{ID: "GHSA-test", Summary: "test vulnerability"}
	rep := &report.Report{
		Repository: v1alpha1.RepositoryInfo{Owner: "acme", Name: "demo"},
		Inventory:  &inventory.Inventory{Components: []*inventory.Component{comp}},
		Match: &vulndb.Result{
			Findings:        []v1alpha1.Finding{{ComponentID: comp.ID, VulnerabilityID: vuln.ID, FixedVersion: "3.2.25"}},
			Vulnerabilities: map[string]*v1alpha1.Vulnerability{vuln.ID: vuln},
		},
	}
	rem := &v1alpha1.Remediation{
		ObjectMeta: v1alpha1.ObjectMeta{Name: "fix"},
		Spec:       v1alpha1.RemediationSpec{ScanName: "scan", ComponentID: comp.ID, VulnerabilityID: vuln.ID},
		Status: v1alpha1.RemediationStatus{
			Kind: v1alpha1.RemediationDependency, DocsID: vuln.ID,
			Branch: "feature/fix", BaseBranch: "main", FromVersion: comp.Version, ToVersion: "3.2.25",
		},
	}
	return rem, rep
}

func fixtureExecutor(t *testing.T) (*stepExecutor, *v1alpha1.Remediation) {
	t.Helper()
	rem, rep := executorFixture()
	e := newStepExecutor(Config{Reports: reportReaderFunc(func(name string) (*report.Report, error) {
		if name != rem.Spec.ScanName {
			t.Fatalf("report lookup = %s", name)
		}
		return rep, nil
	})})
	return e, rem
}

func TestCommandRegistryExcludesReviewAndRejectsUnknown(t *testing.T) {
	e := newStepExecutor(Config{})
	for kind, steps := range pipelines {
		for _, name := range steps {
			_, present := e.commands[name]
			if present != (name != v1alpha1.StepReview) {
				t.Errorf("%s: command %s registered=%v", kind, name, present)
			}
		}
	}
	for _, name := range []v1alpha1.StepName{v1alpha1.StepReview, "unknown"} {
		out := e.Execute(context.Background(), name, nil)
		if !out.Fatal || out.State != v1alpha1.StepFailed || out.Message != "unknown step "+string(name) {
			t.Errorf("unsupported command = %+v", out)
		}
	}
}

func TestExecutorLoadsContextAndReturnsProducedStatus(t *testing.T) {
	e, rem := fixtureExecutor(t)
	out := e.Execute(context.Background(), v1alpha1.StepDeploy, rem)
	if out.State != v1alpha1.StepSkipped || out.Status == nil || out.Status == &rem.Status || out.Status.Branch != rem.Status.Branch {
		t.Fatalf("real deploy command outcome = %+v", out)
	}
	out.Status.Branch = "changed"
	if rem.Status.Branch != "feature/fix" {
		t.Fatal("executor output aliased input status")
	}
}

func TestExecutorReportErrorsAndPanicsAreFatal(t *testing.T) {
	for _, tc := range []struct {
		name string
		read reportReaderFunc
		want string
	}{
		{"read failure", func(string) (*report.Report, error) { return nil, errors.New("report unavailable") }, "report of scan scan: report unavailable"},
		{"missing finding", func(string) (*report.Report, error) { _, r := executorFixture(); r.Match.Findings = nil; return r, nil }, "finding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, rem := fixtureExecutor(t)
			e.Reports = tc.read
			out := e.Execute(context.Background(), v1alpha1.StepApplyFix, rem)
			if !out.Fatal || out.State != v1alpha1.StepFailed || !strings.Contains(out.Message, tc.want) || out.Status != nil {
				t.Fatalf("load failure = %+v", out)
			}
		})
	}
	e, rem := fixtureExecutor(t)
	e.commands[v1alpha1.StepApplyFix] = func(_ context.Context, sc *stepContext) StepResult {
		sc.status.ToVersion = "3.2.26"
		panic("command failed")
	}
	out := e.Execute(context.Background(), v1alpha1.StepApplyFix, rem)
	if !out.Fatal || out.State != v1alpha1.StepFailed || out.Message != "step panicked: command failed" || out.Status.ToVersion != "3.2.26" {
		t.Fatalf("panic result = %+v", out)
	}
}

func TestMatcherPortOnlyRematchesFixedComponent(t *testing.T) {
	e, rem := fixtureExecutor(t)
	sc, err := e.loadContext(context.Background(), rem)
	if err != nil {
		t.Fatal(err)
	}
	want := &vulndb.Result{}
	called := false
	e.Matcher = matcherFunc(func(_ context.Context, inv *inventory.Inventory, ids []string) (*vulndb.Result, error) {
		called = true
		if inv != sc.report.Inventory || !reflect.DeepEqual(ids, []string{sc.comp.ID}) {
			t.Fatalf("match input = %p %v", inv, ids)
		}
		return want, nil
	})
	got, err := e.matchNew(context.Background(), sc.report.Inventory, sc.comp)
	if err != nil || !called || got != want {
		t.Fatalf("match = %p, %v, called=%v", got, err, called)
	}
}

func TestBuildImageFailureIsNonfatal(t *testing.T) {
	e, rem := fixtureExecutor(t)
	sc, err := e.loadContext(context.Background(), rem)
	if err != nil {
		t.Fatal(err)
	}
	sc.comp.Ecosystem = inventory.Image
	sc.comp.Locations = []string{"Dockerfile"}
	called := false
	e.Docker = dockerFunc(func(_ context.Context, args ...string) (string, error) {
		called = true
		if args[0] != "build" {
			t.Fatalf("docker args = %v", args)
		}
		return "build log", errors.New("builder failed")
	})
	out := e.buildImage(context.Background(), sc)
	if !called || out.Fatal || out.State != v1alpha1.StepFailed || out.Log != "build log" || sc.status.Image != "" {
		t.Fatalf("build failure = %+v, image=%s", out, sc.status.Image)
	}
}

type recordingDeployer struct {
	enabled bool
	calls   int
	image   string
	target  *v1alpha1.DeployTarget
	err     error
}

func (d *recordingDeployer) Enabled(*v1alpha1.DeployTarget) bool { return d.enabled }
func (d *recordingDeployer) Deploy(_ context.Context, image string, target *v1alpha1.DeployTarget) (string, string, error) {
	d.calls++
	d.image, d.target = image, target
	return "registry/image:fixed", "deploy log", d.err
}

func TestDeployPortGatesAndPropagatesResults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		err     error
		state   v1alpha1.StepState
	}{
		{"disabled", false, nil, v1alpha1.StepSkipped},
		{"success", true, nil, v1alpha1.StepSucceeded},
		{"failure", true, errors.New("rollout failed"), v1alpha1.StepFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, rem := fixtureExecutor(t)
			d := &recordingDeployer{enabled: tc.enabled, err: tc.err}
			e.Deployer = d
			rem.Spec.Deploy = &v1alpha1.DeployTarget{Namespace: "default", Deployment: "demo", Container: "app"}
			rem.Status.Image = "local/image:fixed"
			rem.Status.Conditions = []v1alpha1.Condition{{Type: v1alpha1.RemediationConditionTestsPassed, Status: v1alpha1.ConditionTrue}}
			out := e.Execute(context.Background(), v1alpha1.StepDeploy, rem)
			if out.State != tc.state || out.Fatal != (tc.err != nil) {
				t.Fatalf("deploy = %+v", out)
			}
			if !tc.enabled {
				if d.calls != 0 {
					t.Fatal("disabled deploy was invoked")
				}
				return
			}
			if d.calls != 1 || d.image != rem.Status.Image || d.target != rem.Spec.Deploy || out.Log != "deploy log" {
				t.Fatalf("deploy inputs/results = %+v, %+v", d, out)
			}
			if tc.err == nil && out.Status.Image != "registry/image:fixed" {
				t.Fatalf("deployed image not returned: %+v", out.Status)
			}
		})
	}
}

type prWorkingCopy struct{ pushed []string }

func (r *prWorkingCopy) Push(_ context.Context, branch string) error {
	r.pushed = append(r.pushed, branch)
	return nil
}
func (*prWorkingCopy) ChangedFiles(context.Context, string) ([]string, error) {
	return []string{"requirements.txt"}, nil
}
func (*prWorkingCopy) ResetHard(context.Context, string) error { return errors.New("unexpected reset") }
func (*prWorkingCopy) CommitAll(context.Context, string, git.Signature) (string, error) {
	return "", errors.New("unexpected commit")
}
func (*prWorkingCopy) CommitPaths(context.Context, string, git.Signature, ...string) (string, error) {
	return "", errors.New("unexpected commit")
}

type descriptionRunner struct{}

func (descriptionRunner) Describe(runner.Spec) string { return "test environment" }
func (descriptionRunner) Run(context.Context, runner.Spec) (runner.Result, error) {
	return runner.Result{}, errors.New("unexpected command execution")
}

func TestPullRequestDraftAndSafetyGuards(t *testing.T) {
	for _, tc := range []struct {
		name      string
		condition v1alpha1.ConditionStatus
		base      string
		token     string
		refused   bool
		draft     bool
	}{
		{"passed", v1alpha1.ConditionTrue, "main", "test-token", false, false},
		{"failed tests draft", v1alpha1.ConditionFalse, "main", "test-token", false, true},
		{"missing tests draft", "", "main", "test-token", false, true},
		{"no branch refuses push", v1alpha1.ConditionTrue, "", "test-token", true, false},
		{"no token refuses push", v1alpha1.ConditionTrue, "main", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, rem := fixtureExecutor(t)
			rem.Status.BaseBranch = tc.base
			rem.Status.Reviewer = "alice"
			rem.Status.Conditions = []v1alpha1.Condition{{Type: v1alpha1.RemediationConditionTestsPassed, Status: tc.condition}}
			e.gitToken, e.Runner = tc.token, descriptionRunner{}
			repo := &prWorkingCopy{}
			var created []github.NewPullRequest
			e.GitHub = pullRequestFunc(func(_ context.Context, ref github.RepoRef, pr github.NewPullRequest) (*github.PullRequest, error) {
				if ref.Owner != "acme" || ref.Name != "demo" || !reflect.DeepEqual(repo.pushed, []string{"feature/fix"}) {
					t.Fatalf("PR before correct push: ref=%+v branches=%v", ref, repo.pushed)
				}
				created = append(created, pr)
				return &github.PullRequest{Number: 7, HTMLURL: "https://example.test/pull/7"}, nil
			})
			sc, err := e.loadContext(context.Background(), rem)
			if err != nil {
				t.Fatal(err)
			}
			sc.repo, sc.dir = repo, t.TempDir()
			out := e.pullRequest(context.Background(), sc)
			if tc.refused {
				if !out.Fatal || out.State != v1alpha1.StepFailed || len(repo.pushed) != 0 || len(created) != 0 {
					t.Fatalf("unsafe PR was attempted: %+v", out)
				}
				return
			}
			if out.State != v1alpha1.StepSucceeded || len(created) != 1 || sc.status.PullRequestURL != "https://example.test/pull/7" {
				t.Fatalf("PR result = %+v, requests=%+v", out, created)
			}
			pr := created[0]
			if pr.Draft != tc.draft || pr.Head != rem.Status.Branch || pr.Base != "main" || !strings.Contains(pr.Body, "alice") {
				t.Fatalf("PR = %+v", pr)
			}
		})
	}
}

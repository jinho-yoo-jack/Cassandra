package remediation

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	apierrors "github.com/jinho-yoo-jack/Cassandra/backend/pkg/api/errors"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/fixer"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/git"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/container"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/generic"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/version"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
)

// stepContext is everything a step needs, loaded once per step.
type stepContext struct {
	rem     *v1alpha1.Remediation
	report  *report.Report
	comp    *inventory.Component
	vuln    *v1alpha1.Vulnerability
	finding v1alpha1.Finding
	repoRef github.RepoRef
	dir     string
	repo    *git.Repo
	// status is a copy the step may modify; produced fields are persisted.
	status *v1alpha1.RemediationStatus
}

func (c *Controller) loadContext(ctx context.Context, rem *v1alpha1.Remediation) (*stepContext, error) {
	rep, err := c.Reports.Get(rem.Spec.ScanName)
	if err != nil {
		return nil, fmt.Errorf("report of scan %s: %w", rem.Spec.ScanName, err)
	}
	comp := rep.Inventory.Component(rem.Spec.ComponentID)
	finding, ok := rep.Finding(rem.Spec.ComponentID, rem.Spec.VulnerabilityID)
	if comp == nil || !ok {
		return nil, apierrors.NewNotFound("finding", rem.Spec.ComponentID+"/"+rem.Spec.VulnerabilityID)
	}
	status := rem.Status
	status.Conditions = append([]v1alpha1.Condition(nil), rem.Status.Conditions...)
	dir := c.Layout.Remediation(rem.Name)
	return &stepContext{
		rem: rem, report: rep, comp: comp, finding: finding,
		vuln:    rep.Match.Vulnerabilities[finding.VulnerabilityID],
		repoRef: github.RepoRef{Owner: rep.Repository.Owner, Name: rep.Repository.Name},
		dir:     dir, repo: git.Open(dir, c.GitHub.Token), status: &status,
	}, nil
}

func (c *Controller) cloneURL(ref github.RepoRef) string {
	if c.CloneURL != nil {
		return c.CloneURL(ref)
	}
	return ref.CloneURL()
}

// targetVersion is the spec override, or the highest fixed version among the
// component's findings so one bump resolves all of them.
func targetVersion(sc *stepContext) string {
	if t := sc.rem.Spec.TargetVersion; t != "" {
		return t
	}
	if sc.finding.FixedVersion == "" {
		return ""
	}
	target := sc.finding.FixedVersion
	for _, f := range sc.report.FindingsFor(sc.comp.ID) {
		if f.FixedVersion != "" && version.Less(string(sc.comp.Ecosystem), strings.TrimPrefix(target, "v"), strings.TrimPrefix(f.FixedVersion, "v")) {
			target = f.FixedVersion
		}
	}
	return target
}

// imagesRunning returns the container components a fix must rewrite.
func imagesRunning(r *report.Report, c *inventory.Component) []*inventory.Component {
	if c.Ecosystem == inventory.Image {
		return []*inventory.Component{c}
	}
	var out []*inventory.Component
	for _, d := range r.Inventory.Dependencies {
		if d.To != c.ID {
			continue
		}
		if img := r.Inventory.Component(d.From); img != nil && img.Type == inventory.TypeContainer {
			out = append(out, img)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// CreateBranch
// ---------------------------------------------------------------------------

func (c *Controller) createBranch(ctx context.Context, sc *stepContext) stepOutcome {
	if err := os.RemoveAll(sc.dir); err != nil {
		return fatal(err, "")
	}
	repo, _, err := git.Clone(ctx, sc.dir, git.CloneOptions{
		URL: c.cloneURL(sc.repoRef), Ref: sc.status.BaseCommit, Depth: 1, Token: c.GitHub.Token,
	})
	if err != nil {
		return fatal(err, "")
	}
	name := sc.comp.Name[strings.LastIndexAny(sc.comp.Name, "/:")+1:]
	branch := "feature/" + generic.Slug(sc.status.DocsID+"-"+name, 60)
	if err := repo.CreateBranch(ctx, branch); err != nil {
		return fatal(err, "")
	}
	sc.status.Branch = branch
	return succeeded(fmt.Sprintf("%s 브랜치를 %s(%s)에서 생성", branch, sc.status.BaseBranch, short(sc.status.BaseCommit)))
}

func short(s string) string { return s[:min(len(s), 12)] }

// ---------------------------------------------------------------------------
// ApplyFix
// ---------------------------------------------------------------------------

func (c *Controller) applyFix(ctx context.Context, sc *stepContext) stepOutcome {
	target := targetVersion(sc)
	if target == "" {
		return fatal(fmt.Errorf("%s에 대한 패치 버전이 아직 없습니다 — 수동 완화 조치가 필요합니다", sc.vuln.DisplayID()), "")
	}
	// Start from the scanned commit so a re-run is idempotent.
	if err := sc.repo.ResetHard(ctx, sc.status.BaseCommit); err != nil {
		return fatal(err, "")
	}
	f, err := fixer.For(sc.comp)
	if err != nil {
		return fatal(err, "")
	}
	res, err := f.Fix(ctx, &fixer.Request{
		Root: sc.dir, Component: sc.comp, Projects: sc.report.Inventory.ProjectsOf(sc.comp),
		Images: imagesRunning(sc.report, sc.comp), Target: target,
		Runner: c.Runner, Toolchains: c.Toolchains, TagExists: c.tagExists,
	})
	if err != nil {
		if isManual(err) {
			return fatal(fmt.Errorf("수동 조치 필요: %w", err), res.Log)
		}
		return fatal(err, res.Log)
	}
	changed, err := sc.repo.ChangedFiles(ctx, sc.status.BaseCommit)
	if err != nil {
		return fatal(err, res.Log)
	}
	if len(changed) == 0 {
		return fatal(fmt.Errorf("fix produced no changes"), res.Log)
	}
	sc.status.ToVersion = target
	out := succeeded(res.Summary)
	out.log = res.Log + "\n\nChanged files:\n" + strings.Join(changed, "\n")
	return out
}

func (c *Controller) tagExists(ctx context.Context, ref string) bool {
	_, err := c.Docker.Exec(ctx, "manifest", "inspect", ref)
	return err == nil
}

// ---------------------------------------------------------------------------
// WriteTestScenarios
// ---------------------------------------------------------------------------

func (c *Controller) docData(ctx context.Context, sc *stepContext) *docData {
	changed, _ := sc.repo.ChangedFiles(ctx, sc.status.BaseCommit)
	var fixSummary string
	if st := sc.rem.Status.Step(v1alpha1.StepApplyFix); st != nil {
		fixSummary = st.Message
	}
	d := &docData{
		DocsID: sc.status.DocsID, Vuln: sc.vuln, Comp: sc.comp, Finding: sc.finding,
		From: sc.status.FromVersion, To: sc.status.ToVersion, Kind: sc.status.Kind,
		Branch: sc.status.Branch, BaseBranch: sc.status.BaseBranch, BaseCommit: sc.status.BaseCommit,
		FixSummary: fixSummary, ChangedFiles: withoutDocs(changed, docsDir(sc.status.DocsID)),
		DependencyPath: vulndbPath(sc), Related: relatedFindings(sc, sc.status.ToVersion),
		Image: sc.status.Image, Deploy: sc.rem.Spec.Deploy,
		Environment: c.environment(sc), GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Reviewer: sc.status.Reviewer, ReviewComment: sc.status.ReviewComment,
	}
	for _, s := range c.scenarios(sc) {
		d.Scenarios = append(d.Scenarios, scenarioRow{ID: s.id, Title: s.title, Method: s.method, Expected: s.expected})
	}
	if len(sc.status.TestResults) > 0 {
		d.setResults(sc.status.TestResults, time.Now())
	}
	return d
}

func withoutDocs(files []string, docs string) []string {
	var out []string
	for _, f := range files {
		if !strings.HasPrefix(f, docs+"/") {
			out = append(out, f)
		}
	}
	return out
}

func vulndbPath(sc *stepContext) string {
	ids := sc.report.Inventory.PathTo(sc.comp.ID)
	labels := make([]string, 0, len(ids))
	for _, id := range ids {
		if c := sc.report.Inventory.Component(id); c != nil {
			labels = append(labels, c.Name+"@"+c.Version)
		} else {
			labels = append(labels, strings.TrimPrefix(id, "project:"))
		}
	}
	return strings.Join(labels, " → ")
}

func (c *Controller) writeTestScenarios(ctx context.Context, sc *stepContext) stepOutcome {
	paths, err := writeDocs(sc.dir, c.docData(ctx, sc), DocVulnerabilityDetails, DocRemediation, DocTestScenarios)
	if err != nil {
		return fatal(err, "")
	}
	sc.status.Docs = paths
	return succeeded(fmt.Sprintf("%s 에 문서 3종 작성", docsDir(sc.status.DocsID)))
}

// ---------------------------------------------------------------------------
// BuildImage
// ---------------------------------------------------------------------------

func isDockerfile(p string) bool {
	b := path.Base(p)
	return b == "Dockerfile" || b == "Containerfile" || strings.HasPrefix(b, "Dockerfile.") || strings.HasSuffix(b, ".Dockerfile")
}

func (c *Controller) buildImage(ctx context.Context, sc *stepContext) stepOutcome {
	var dockerfile string
	for _, img := range imagesRunning(sc.report, sc.comp) {
		for _, loc := range img.Locations {
			if isDockerfile(loc) {
				dockerfile = loc
				break
			}
		}
	}
	if dockerfile != "" {
		tag := fmt.Sprintf("cassandra/%s:%s-%s", generic.Slug(sc.repoRef.Name, 40),
			generic.Slug(strings.TrimPrefix(sc.status.Branch, "feature/"), 60), time.Now().UTC().Format("20060102150405"))
		args := []string{"build", "--pull", "-t", tag, "-f", filepath.Join(sc.dir, dockerfile), filepath.Join(sc.dir, path.Dir(dockerfile))}
		out, err := c.Docker.Exec(ctx, args...)
		if err != nil {
			// Not fatal: the runtime scenarios report the failure for review.
			return stepOutcome{state: v1alpha1.StepFailed, message: "이미지 빌드 실패: " + err.Error(), log: out}
		}
		sc.status.Image = tag
		return stepOutcome{state: v1alpha1.StepSucceeded, message: fmt.Sprintf("%s 로 이미지 %s 빌드", dockerfile, tag), log: out}
	}

	// The image is only referenced (compose, Kubernetes): pull the new tag.
	inv, err := inventory.Extract(ctx, os.DirFS(sc.dir), c.Extractors, c.Log)
	if err != nil {
		return fatal(err, "")
	}
	for _, img := range inv.Components {
		if img.Image == nil || img.Image.Repository != firstImageRepo(sc) {
			continue
		}
		if container.VersionFromTag(img.Image.Tag) != sc.status.ToVersion {
			continue
		}
		ref := container.String(img.Image)
		out, err := c.Docker.Exec(ctx, "pull", ref)
		if err != nil {
			return stepOutcome{state: v1alpha1.StepFailed, message: "이미지 pull 실패: " + err.Error(), log: out}
		}
		sc.status.Image = ref
		return stepOutcome{state: v1alpha1.StepSucceeded, message: "Dockerfile이 없어 수정된 이미지 " + ref + " 를 pull", log: out}
	}
	return stepOutcome{state: v1alpha1.StepFailed, message: "수정된 이미지 참조를 찾을 수 없습니다"}
}

func firstImageRepo(sc *stepContext) string {
	if imgs := imagesRunning(sc.report, sc.comp); len(imgs) > 0 && imgs[0].Image != nil {
		return imgs[0].Image.Repository
	}
	return ""
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

func (c *Controller) test(ctx context.Context, sc *stepContext) stepOutcome {
	// Commit the fix and the scenarios first, so build artefacts created by
	// the tests (node_modules, target/) can never be committed.
	msg := fmt.Sprintf("fix(security): bump %s %s → %s (%s)\n\n%s\n\nGenerated by cassandra",
		sc.comp.Name, sc.status.FromVersion, sc.status.ToVersion, sc.status.DocsID, sc.vuln.Summary)
	if _, err := sc.repo.CommitAll(ctx, msg, c.Author); err != nil {
		return fatal(err, "")
	}

	results := c.runScenarios(ctx, sc)
	sc.status.TestResults = results
	passed := true
	var failed []string
	for _, r := range results {
		if r.Status == v1alpha1.TestFailed {
			passed = false
			failed = append(failed, r.ID)
		}
	}

	if _, err := writeDocs(sc.dir, c.docData(ctx, sc), DocTestScenarios); err != nil {
		return fatal(err, "")
	}
	commit, err := sc.repo.CommitPaths(ctx, fmt.Sprintf("docs(cve): %s test results", sc.status.DocsID), c.Author, path.Join(docsDir(sc.status.DocsID), DocTestScenarios))
	if err != nil {
		return fatal(err, "")
	}
	sc.status.Commit = commit

	cond := v1alpha1.Condition{Type: v1alpha1.RemediationConditionTestsPassed, Status: v1alpha1.ConditionTrue, Reason: "AllPassed", LastTransitionTime: time.Now().UTC()}
	if !passed {
		cond.Status, cond.Reason, cond.Message = v1alpha1.ConditionFalse, "ScenariosFailed", strings.Join(failed, ", ")
	}
	v1alpha1.SetCondition(&sc.status.Conditions, cond)
	if !passed {
		return stepOutcome{state: v1alpha1.StepFailed, message: fmt.Sprintf("%d개 시나리오 실패 (%s) — 검토 필요", len(failed), strings.Join(failed, ", "))}
	}
	return succeeded(fmt.Sprintf("%d개 시나리오 통과", len(results)))
}

func testsPassed(s *v1alpha1.RemediationStatus) bool {
	c := v1alpha1.FindCondition(s.Conditions, v1alpha1.RemediationConditionTestsPassed)
	return c != nil && c.Status == v1alpha1.ConditionTrue
}

// ---------------------------------------------------------------------------
// Deploy
// ---------------------------------------------------------------------------

func (c *Controller) deploy(ctx context.Context, sc *stepContext) stepOutcome {
	switch {
	case !testsPassed(sc.status):
		return skipped("테스트 실패로 배포하지 않음")
	case sc.status.Image == "":
		return skipped("배포할 이미지가 없음")
	case !c.Deployer.Enabled(sc.rem.Spec.Deploy):
		return skipped("배포 대상 미설정 (--registry 또는 spec.deploy)")
	}
	ref, log, err := c.Deployer.Deploy(ctx, sc.status.Image, sc.rem.Spec.Deploy)
	if err != nil {
		return fatal(err, log)
	}
	sc.status.Image = ref
	out := succeeded("배포 완료: " + ref)
	out.log = log
	return out
}

// ---------------------------------------------------------------------------
// PullRequest
// ---------------------------------------------------------------------------

func (c *Controller) pullRequest(ctx context.Context, sc *stepContext) stepOutcome {
	if sc.status.BaseBranch == "" {
		return fatal(fmt.Errorf("스캔 기준이 브랜치가 아니어서(태그/커밋) PR을 만들 수 없습니다. 브랜치 %s 는 로컬(%s)에 있습니다", sc.status.Branch, sc.dir), "")
	}
	if c.GitHub.Token == "" {
		return fatal(fmt.Errorf("GitHub 토큰이 없어 push/PR을 할 수 없습니다(--github-token). 브랜치 %s 는 로컬(%s)에 있습니다", sc.status.Branch, sc.dir), "")
	}
	if err := sc.repo.Push(ctx, sc.status.Branch); err != nil {
		return fatal(err, "")
	}
	d := c.docData(ctx, sc)
	body, err := render("pull-request.md", d)
	if err != nil {
		return fatal(err, "")
	}
	draft := !testsPassed(sc.status)
	pr, err := c.GitHub.CreatePullRequest(ctx, sc.repoRef, github.NewPullRequest{
		Title: fmt.Sprintf("fix(security): %s — %s %s → %s", sc.status.DocsID, sc.comp.Name, sc.status.FromVersion, sc.status.ToVersion),
		Head:  sc.status.Branch, Base: sc.status.BaseBranch, Body: body, Draft: draft,
	})
	if err != nil {
		return fatal(err, "")
	}
	sc.status.PullRequestURL = pr.HTMLURL
	kind := "PR"
	if draft {
		kind = "Draft PR"
	}
	return succeeded(fmt.Sprintf("%s #%d 생성: %s", kind, pr.Number, pr.HTMLURL))
}

// matchNew re-matches one component of the re-extracted inventory.
func (c *Controller) matchNew(ctx context.Context, inv *inventory.Inventory, comp *inventory.Component) (*vulndb.Result, error) {
	return c.Matcher.MatchComponents(ctx, inv, []string{comp.ID})
}

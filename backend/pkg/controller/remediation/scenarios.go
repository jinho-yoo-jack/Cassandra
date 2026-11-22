package remediation

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/fixer"
	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory/extractor/container"
	"github.com/jinho-yoo-jack/vulngraph/pkg/runner"
	"github.com/jinho-yoo-jack/vulngraph/pkg/version"
)

// scenario is one entry of test-scenarios.md and the check that runs it.
type scenario struct {
	id, title, method, expected string
	run                         func(ctx context.Context, env *testEnv) (v1alpha1.TestResultStatus, string)
}

// testEnv is shared by the scenarios of one run.
type testEnv struct {
	sc *stepContext
	// inv is the inventory re-extracted from the fixed working copy.
	inv     *inventory.Inventory
	invErr  error
	newComp *inventory.Component
	// container is the ID of the started container (image scenarios).
	container string
}

func (c *Controller) environment(sc *stepContext) string {
	if sc.status.Kind == v1alpha1.RemediationImage {
		return "Docker (이미지 빌드 및 컨테이너 실행)"
	}
	toolchain, _, _ := buildCommands(sc.dir, firstProject(sc))
	return c.Runner.Describe(runner.Spec{Image: c.Toolchains[toolchain]})
}

func firstProject(sc *stepContext) *inventory.Project {
	if ps := sc.report.Inventory.ProjectsOf(sc.comp); len(ps) > 0 {
		return ps[0]
	}
	return &inventory.Project{Dir: ".", Ecosystem: sc.comp.Ecosystem}
}

func (c *Controller) scenarios(sc *stepContext) []scenario {
	name, target := sc.comp.Name, sc.status.ToVersion
	common := []scenario{
		{
			id: "TS-01", title: "버전 검증",
			method:   "수정된 매니페스트/락파일을 다시 분석해 해석된 버전 확인",
			expected: fmt.Sprintf("`%s` ≥ %s", name, target),
			run:      c.checkVersion,
		},
		{
			id: "TS-02", title: "취약점 재검증",
			method:   "수정된 버전으로 OSV/NVD 재질의",
			expected: fmt.Sprintf("%s 미검출", sc.vuln.DisplayID()),
			run:      c.checkVulnerabilityGone,
		},
	}
	if sc.status.Kind == v1alpha1.RemediationImage {
		known, _ := container.LookupProcess(firstImageRepo(sc))
		return append(common,
			scenario{id: "TS-03", title: "이미지 빌드", method: "`docker build` (또는 수정된 태그 pull)", expected: "이미지 생성 성공", run: c.checkImageBuilt},
			scenario{id: "TS-04", title: "컨테이너 기동", method: "`docker run -d` 후 상태 확인", expected: "5초 후 Running", run: c.checkContainerRunning},
			scenario{id: "TS-05", title: "프로세스 버전 확인", method: "`" + strings.Join(known.VersionCommand, " ") + "`", expected: "출력에 " + target + " 포함", run: c.checkProcessVersion},
			scenario{id: "TS-06", title: "설정 검증", method: "`" + strings.Join(known.ConfigTestCommand, " ") + "`", expected: "종료 코드 0", run: c.checkConfig},
			scenario{id: "TS-07", title: "HTTP 헬스 체크", method: fmt.Sprintf("컨테이너 %d 포트로 GET /", known.Port), expected: "HTTP 상태 < 500", run: c.checkHTTP},
		)
	}
	_, build, test := buildCommands(sc.dir, firstProject(sc))
	return append(common,
		scenario{id: "TS-03", title: "신규 취약점 유입 확인", method: "변경된 버전의 다른 취약점 조회", expected: "HIGH 이상 신규 취약점 없음", run: c.checkNoNewHigh},
		scenario{id: "TS-04", title: "빌드", method: "`" + orNone(build) + "`", expected: "종료 코드 0", run: c.runCommand(build)},
		scenario{id: "TS-05", title: "단위 테스트", method: "`" + orNone(test) + "`", expected: "기존 테스트 전부 통과", run: c.runCommand(test)},
	)
}

func orNone(s string) string {
	if s == "" {
		return "해당 없음"
	}
	return s
}

// runScenarios executes every scenario and returns their results.
func (c *Controller) runScenarios(ctx context.Context, sc *stepContext) []v1alpha1.TestResult {
	env := &testEnv{sc: sc}
	env.inv, env.invErr = inventory.Extract(ctx, os.DirFS(sc.dir), c.Extractors, c.Log)
	if env.invErr == nil {
		env.newComp = findSame(env.inv, sc.comp)
	}
	defer func() {
		if env.container != "" {
			_, _ = c.Docker.Exec(context.WithoutCancel(ctx), "rm", "-f", env.container)
		}
	}()

	var results []v1alpha1.TestResult
	for _, s := range c.scenarios(sc) {
		start := time.Now()
		status, detail := s.run(ctx, env)
		results = append(results, v1alpha1.TestResult{
			ID: s.id, Title: s.title, Status: status, Detail: tailDetail(detail),
			Duration: time.Since(start).Round(time.Millisecond).String(),
		})
	}
	return results
}

func tailDetail(s string) string {
	const max = 4000
	s = strings.TrimSpace(s)
	if len(s) > max {
		return "…\n" + s[len(s)-max:]
	}
	return s
}

// findSame finds the component with the same name and ecosystem, preferring
// one in the same manifests, in a re-extracted inventory.
func findSame(inv *inventory.Inventory, c *inventory.Component) *inventory.Component {
	var fallback *inventory.Component
	for _, n := range inv.Components {
		if n.Ecosystem != c.Ecosystem || n.Name != c.Name {
			continue
		}
		for _, l := range n.Locations {
			for _, ol := range c.Locations {
				if l == ol {
					return n
				}
			}
		}
		fallback = n
	}
	return fallback
}

func (c *Controller) checkVersion(_ context.Context, env *testEnv) (v1alpha1.TestResultStatus, string) {
	if env.invErr != nil {
		return v1alpha1.TestFailed, env.invErr.Error()
	}
	if env.newComp == nil {
		return v1alpha1.TestFailed, "수정 후 인벤토리에서 컴포넌트를 찾지 못함"
	}
	got, want := strings.TrimPrefix(env.newComp.Version, "v"), strings.TrimPrefix(env.sc.status.ToVersion, "v")
	if version.Compare(string(env.newComp.Ecosystem), got, want) < 0 {
		return v1alpha1.TestFailed, fmt.Sprintf("해석된 버전 %s < 목표 %s", env.newComp.Version, env.sc.status.ToVersion)
	}
	return v1alpha1.TestPassed, fmt.Sprintf("%s@%s (%s)", env.newComp.Name, env.newComp.Version, strings.Join(env.newComp.Locations, ", "))
}

func (c *Controller) checkVulnerabilityGone(ctx context.Context, env *testEnv) (v1alpha1.TestResultStatus, string) {
	if env.newComp == nil {
		return v1alpha1.TestFailed, "검증할 컴포넌트 없음"
	}
	res, err := c.matchNew(ctx, env.inv, env.newComp)
	if err != nil {
		return v1alpha1.TestFailed, "재질의 실패: " + err.Error()
	}
	target := env.sc.vuln.DisplayID()
	for _, v := range res.Vulnerabilities {
		if v.DisplayID() == target || v.ID == env.sc.vuln.ID {
			return v1alpha1.TestFailed, fmt.Sprintf("%s@%s 에서 %s 가 여전히 검출됨", env.newComp.Name, env.newComp.Version, target)
		}
	}
	return v1alpha1.TestPassed, fmt.Sprintf("%s@%s: %s 미검출 (남은 취약점 %d건)", env.newComp.Name, env.newComp.Version, target, len(res.Vulnerabilities))
}

func (c *Controller) checkNoNewHigh(ctx context.Context, env *testEnv) (v1alpha1.TestResultStatus, string) {
	if env.newComp == nil {
		return v1alpha1.TestFailed, "검증할 컴포넌트 없음"
	}
	res, err := c.matchNew(ctx, env.inv, env.newComp)
	if err != nil {
		return v1alpha1.TestFailed, "재질의 실패: " + err.Error()
	}
	var high, other []string
	for _, v := range res.Vulnerabilities {
		if v.Severity.Rank() >= v1alpha1.SeverityHigh.Rank() {
			high = append(high, fmt.Sprintf("%s (%s)", v.DisplayID(), v.Severity))
		} else {
			other = append(other, fmt.Sprintf("%s (%s)", v.DisplayID(), v.Severity))
		}
	}
	if len(high) > 0 {
		return v1alpha1.TestFailed, "HIGH 이상 취약점: " + strings.Join(high, ", ")
	}
	if len(other) > 0 {
		return v1alpha1.TestPassed, "HIGH 미만 잔여 취약점: " + strings.Join(other, ", ")
	}
	return v1alpha1.TestPassed, "잔여 취약점 없음"
}

func (c *Controller) runCommand(script string) func(context.Context, *testEnv) (v1alpha1.TestResultStatus, string) {
	return func(ctx context.Context, env *testEnv) (v1alpha1.TestResultStatus, string) {
		if script == "" {
			return v1alpha1.TestSkipped, "이 생태계에서 실행할 명령이 정의되지 않음"
		}
		p := firstProject(env.sc)
		toolchain, _, _ := buildCommands(env.sc.dir, p)
		res, err := c.Runner.Run(ctx, runner.Spec{
			Image: c.Toolchains[toolchain], Root: env.sc.dir, WorkDir: projectDir(p), Script: script, Timeout: 30 * time.Minute,
		})
		if err != nil {
			return v1alpha1.TestFailed, err.Error() + "\n" + res.Output
		}
		if res.ExitCode != 0 {
			return v1alpha1.TestFailed, fmt.Sprintf("exit %d\n%s", res.ExitCode, res.Output)
		}
		return v1alpha1.TestPassed, res.Output
	}
}

func projectDir(p *inventory.Project) string {
	if p.Dir == "." {
		return ""
	}
	return p.Dir
}

// buildCommands returns the toolchain, build and test scripts of a project.
func buildCommands(root string, p *inventory.Project) (toolchain, build, test string) {
	exists := func(name string) bool {
		_, err := os.Stat(path.Join(root, p.Dir, name))
		return err == nil
	}
	switch p.Ecosystem {
	case inventory.Go:
		return fixer.ToolchainGo, "go build ./...", "go test ./..."
	case inventory.NPM:
		install := "npm install --no-audit --no-fund"
		switch path.Base(p.Lockfile) {
		case "package-lock.json", "npm-shrinkwrap.json":
			install = "npm ci --no-audit --no-fund"
		case "pnpm-lock.yaml":
			install = "npx -y pnpm@9 install --frozen-lockfile"
		case "yarn.lock":
			install = "npx -y yarn@1.22.22 install --frozen-lockfile --non-interactive"
		}
		return fixer.ToolchainNode, install + " && npm run build --if-present", install + " && npm test --if-present"
	case inventory.PyPI:
		install := "pip install -q ."
		if strings.HasSuffix(p.Manifest, ".txt") {
			install = "pip install -q -r " + path.Base(p.Manifest)
		}
		return fixer.ToolchainPython, install,
			install + " && pip install -q pytest && { python -m pytest -q; rc=$?; [ $rc -eq 5 ] && echo 'no tests collected' && exit 0; exit $rc; }"
	case inventory.Maven:
		if path.Base(p.Manifest) == "pom.xml" {
			mvn := "mvn"
			if exists("mvnw") {
				mvn = "./mvnw"
			}
			return fixer.ToolchainMaven, mvn + " -B -q -DskipTests package", mvn + " -B -q test"
		}
		gradle := "gradle --no-daemon"
		if exists("gradlew") {
			gradle = "./gradlew --no-daemon"
		}
		return fixer.ToolchainGradle, gradle + " build -x test", gradle + " test"
	case inventory.CratesIO:
		return fixer.ToolchainRust, "cargo build", "cargo test"
	case inventory.RubyGems:
		return fixer.ToolchainRuby, "bundle install", ""
	case inventory.Packagist:
		return fixer.ToolchainPHP, "composer install --no-interaction", ""
	}
	return "", "", ""
}

// ---------------------------------------------------------------------------
// Image scenarios
// ---------------------------------------------------------------------------

func (c *Controller) checkImageBuilt(_ context.Context, env *testEnv) (v1alpha1.TestResultStatus, string) {
	st := env.sc.rem.Status.Step(v1alpha1.StepBuildImage)
	if env.sc.status.Image == "" {
		msg := "이미지 없음"
		if st != nil {
			msg = st.Message
		}
		return v1alpha1.TestFailed, msg
	}
	return v1alpha1.TestPassed, env.sc.status.Image
}

func (c *Controller) startContainer(ctx context.Context, env *testEnv) (string, error) {
	if env.container != "" {
		return env.container, nil
	}
	if env.sc.status.Image == "" {
		return "", fmt.Errorf("이미지가 없어 실행할 수 없음")
	}
	args := []string{"run", "-d"}
	if known, ok := container.LookupProcess(firstImageRepo(env.sc)); ok && known.Port > 0 {
		args = append(args, "-p", fmt.Sprintf("127.0.0.1::%d", known.Port))
	}
	id, err := c.Docker.Exec(ctx, append(args, env.sc.status.Image)...)
	if err != nil {
		return "", err
	}
	env.container = strings.TrimSpace(id)
	return env.container, nil
}

func (c *Controller) checkContainerRunning(ctx context.Context, env *testEnv) (v1alpha1.TestResultStatus, string) {
	id, err := c.startContainer(ctx, env)
	if err != nil {
		return v1alpha1.TestFailed, err.Error()
	}
	time.Sleep(5 * time.Second)
	running, err := c.Docker.Exec(ctx, "inspect", "-f", "{{.State.Running}}", id)
	if err != nil || running != "true" {
		logs, _ := c.Docker.Exec(ctx, "logs", "--tail", "50", id)
		return v1alpha1.TestFailed, "컨테이너가 실행 중이 아님\n" + logs
	}
	return v1alpha1.TestPassed, "container " + short(id) + " running"
}

func (c *Controller) execInContainer(ctx context.Context, env *testEnv, cmd []string) (v1alpha1.TestResultStatus, string) {
	if len(cmd) == 0 {
		return v1alpha1.TestSkipped, "이 이미지에 정의된 명령 없음"
	}
	id, err := c.startContainer(ctx, env)
	if err != nil {
		return v1alpha1.TestFailed, err.Error()
	}
	out, err := c.Docker.Exec(ctx, append([]string{"exec", id}, cmd...)...)
	if err != nil {
		return v1alpha1.TestFailed, err.Error() + "\n" + out
	}
	return v1alpha1.TestPassed, out
}

func (c *Controller) checkProcessVersion(ctx context.Context, env *testEnv) (v1alpha1.TestResultStatus, string) {
	known, ok := container.LookupProcess(firstImageRepo(env.sc))
	if !ok {
		return v1alpha1.TestSkipped, "알려진 프로세스가 아님"
	}
	status, out := c.execInContainer(ctx, env, known.VersionCommand)
	if status == v1alpha1.TestPassed && !strings.Contains(out, env.sc.status.ToVersion) {
		return v1alpha1.TestFailed, fmt.Sprintf("출력에 %s 가 없음: %s", env.sc.status.ToVersion, out)
	}
	return status, out
}

func (c *Controller) checkConfig(ctx context.Context, env *testEnv) (v1alpha1.TestResultStatus, string) {
	known, _ := container.LookupProcess(firstImageRepo(env.sc))
	return c.execInContainer(ctx, env, known.ConfigTestCommand)
}

func (c *Controller) checkHTTP(ctx context.Context, env *testEnv) (v1alpha1.TestResultStatus, string) {
	known, ok := container.LookupProcess(firstImageRepo(env.sc))
	if !ok || known.Port == 0 {
		return v1alpha1.TestSkipped, "HTTP 포트가 정의되지 않음"
	}
	id, err := c.startContainer(ctx, env)
	if err != nil {
		return v1alpha1.TestFailed, err.Error()
	}
	hostPort, err := c.Docker.Exec(ctx, "port", id, fmt.Sprintf("%d/tcp", known.Port))
	if err != nil {
		return v1alpha1.TestFailed, err.Error()
	}
	addr := strings.Split(hostPort, "\n")[0]
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for range 10 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return v1alpha1.TestPassed, fmt.Sprintf("GET http://%s/ → %s", addr, resp.Status)
			}
			lastErr = fmt.Errorf("HTTP %s", resp.Status)
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	return v1alpha1.TestFailed, lastErr.Error()
}

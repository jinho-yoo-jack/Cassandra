package fixer

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/container"
)

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

type goFixer struct{}

func (goFixer) Fix(ctx context.Context, req *Request) (Result, error) {
	var logs []string
	for _, p := range req.Projects {
		if req.Component.Name == "stdlib" {
			// Standard library fixes ship with the toolchain.
			data, err := req.read(p.Manifest)
			if err != nil {
				return Result{}, err
			}
			f, err := modfile.Parse(p.Manifest, []byte(data), nil)
			if err != nil {
				return Result{}, err
			}
			if err := f.AddToolchainStmt("go" + req.Target); err != nil {
				return Result{}, err
			}
			out, err := f.Format()
			if err != nil {
				return Result{}, err
			}
			if err := req.write(p.Manifest, string(out)); err != nil {
				return Result{}, err
			}
			continue
		}
		script := fmt.Sprintf("go get %s && go mod tidy", shellQuote(req.Component.Name+"@"+req.Target))
		out, err := req.exec(ctx, ToolchainGo, dir(p), script)
		logs = append(logs, out)
		if err != nil {
			return Result{Log: strings.Join(logs, "\n")}, err
		}
	}
	summary := fmt.Sprintf("`go get %s@%s && go mod tidy`", req.Component.Name, req.Target)
	if req.Component.Name == "stdlib" {
		summary = fmt.Sprintf("go.mod에 `toolchain go%s` 지정", req.Target)
	}
	return Result{Summary: summary, Log: strings.Join(logs, "\n")}, nil
}

// ---------------------------------------------------------------------------
// npm / pnpm / yarn
// ---------------------------------------------------------------------------

type npmFixer struct{}

func (npmFixer) Fix(ctx context.Context, req *Request) (Result, error) {
	var (
		logs    []string
		summary string
	)
	name, target := req.Component.Name, req.Target
	for _, p := range req.Projects {
		pkgJSON, err := req.read(p.Manifest)
		if err != nil {
			return Result{}, err
		}
		direct, dev, spec0 := declares(pkgJSON, name)
		// Keep exact pins exact: npm would otherwise write "^<target>".
		exact := flag(spec0 != "" && spec0[0] >= '0' && spec0[0] <= '9', "--save-exact ")
		manager := path.Base(p.Lockfile)
		if manager == "yarn.lock" && req.exists(path.Join(p.Dir, ".yarnrc.yml")) {
			return Result{}, fmt.Errorf("yarn berry: %w", ErrManual)
		}
		spec := shellQuote(name + "@" + target)
		var script string
		switch {
		case direct && manager == "pnpm-lock.yaml":
			script = "npx -y pnpm@9 add --lockfile-only --ignore-scripts " + exact + flag(dev, "-D ") + spec
		case direct && manager == "yarn.lock":
			script = "npx -y yarn@1.22.22 add --ignore-scripts --non-interactive " + flag(exact != "", "--exact ") + flag(dev, "-D ") + spec
		case direct:
			script = "npm install --package-lock-only --ignore-scripts --no-audit --no-fund " + exact + flag(dev, "--save-dev ") + spec
		case manager == "pnpm-lock.yaml":
			script = fmt.Sprintf("npm pkg set %s && npx -y pnpm@9 install --lockfile-only --ignore-scripts", shellQuote("pnpm.overrides["+name+"]="+target))
		case manager == "yarn.lock":
			script = fmt.Sprintf("npm pkg set %s && npx -y yarn@1.22.22 install --ignore-scripts --non-interactive", shellQuote("resolutions["+name+"]="+target))
		default:
			script = fmt.Sprintf("npm pkg set %s && npm install --package-lock-only --ignore-scripts --no-audit --no-fund", shellQuote("overrides["+name+"]="+target))
		}
		if direct {
			summary = fmt.Sprintf("직접 의존성 %s를 %s로 업그레이드", name, target)
		} else {
			summary = fmt.Sprintf("전이 의존성 %s를 package.json overrides/resolutions로 %s에 고정", name, target)
		}
		out, err := req.exec(ctx, ToolchainNode, dir(p), script)
		logs = append(logs, "$ "+script, out)
		if err != nil {
			return Result{Log: strings.Join(logs, "\n")}, err
		}
	}
	return Result{Summary: summary, Log: strings.Join(logs, "\n")}, nil
}

// declares reports whether package.json declares name, whether as a dev
// dependency, and the declared version spec.
func declares(pkgJSON, name string) (direct, dev bool, spec string) {
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if json.Unmarshal([]byte(pkgJSON), &pkg) != nil {
		return false, false, ""
	}
	if v, ok := pkg.Dependencies[name]; ok {
		return true, false, v
	}
	if v, ok := pkg.OptionalDependencies[name]; ok {
		return true, false, v
	}
	v, ok := pkg.DevDependencies[name]
	return ok, ok, v
}

func flag(on bool, f string) string {
	if on {
		return f
	}
	return ""
}

func (r *Request) exists(rel string) bool {
	_, err := r.read(rel)
	return err == nil
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

type pythonFixer struct{}

func (pythonFixer) Fix(ctx context.Context, req *Request) (Result, error) {
	var (
		logs    []string
		summary string
	)
	for _, p := range req.Projects {
		switch {
		case path.Base(p.Lockfile) == "uv.lock":
			script := "pip install -q uv && uv lock --upgrade-package " + shellQuote(req.Component.Name+"=="+req.Target)
			out, err := req.exec(ctx, ToolchainPython, dir(p), script)
			logs = append(logs, "$ "+script, out)
			if err != nil {
				return Result{Log: strings.Join(logs, "\n")}, err
			}
			summary = fmt.Sprintf("`uv lock --upgrade-package %s==%s`", req.Component.Name, req.Target)
		case strings.HasSuffix(p.Manifest, ".txt"):
			content, err := req.read(p.Manifest)
			if err != nil {
				return Result{}, err
			}
			if err := req.write(p.Manifest, pinRequirement(content, req.Component.Name, req.Target)); err != nil {
				return Result{}, err
			}
			summary = fmt.Sprintf("requirements에 `%s==%s` 고정", req.Component.Name, req.Target)
		default:
			return Result{}, fmt.Errorf("%s: %w", p.Manifest, ErrManual)
		}
	}
	return Result{Summary: summary, Log: strings.Join(logs, "\n")}, nil
}

// pinRequirement replaces the requirement line of name, or appends one.
func pinRequirement(content, name, target string) string {
	norm := inventory.NormalizePyPI(name)
	lines := strings.Split(content, "\n")
	re := regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===|==|~=|>=|>|<=|<|!=)?[^;#]*(.*)$`)
	for i, l := range lines {
		m := re.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil || inventory.NormalizePyPI(m[1]) != norm {
			continue
		}
		rest := strings.TrimSpace(m[4])
		lines[i] = m[1] + m[2] + "==" + target
		if rest != "" {
			lines[i] += " " + rest
		}
		return strings.Join(lines, "\n")
	}
	suffix := ""
	if !strings.HasSuffix(content, "\n") && content != "" {
		suffix = "\n"
	}
	return content + suffix + fmt.Sprintf("%s>=%s  # cassandra: transitive dependency pin\n", name, target)
}

// ---------------------------------------------------------------------------
// Maven / Gradle
// ---------------------------------------------------------------------------

type mavenFixer struct{}

var (
	dependencyBlock = regexp.MustCompile(`(?s)<dependency>.*?</dependency>`)
	versionTag      = regexp.MustCompile(`<version>\s*([^<]+?)\s*</version>`)
)

func (mavenFixer) Fix(ctx context.Context, req *Request) (Result, error) {
	group, artifact, _ := strings.Cut(req.Component.Name, ":")
	for _, p := range req.Projects {
		content, err := req.read(p.Manifest)
		if err != nil {
			return Result{}, err
		}
		var updated string
		switch path.Base(p.Manifest) {
		case "pom.xml":
			updated, err = bumpPom(content, group, artifact, req.Component.Version, req.Target)
		default:
			updated, err = bumpGradle(req, p, content, group, artifact, req.Component.Version, req.Target)
		}
		if err != nil {
			return Result{}, fmt.Errorf("%s: %w", p.Manifest, err)
		}
		if err := req.write(p.Manifest, updated); err != nil {
			return Result{}, err
		}
	}
	return Result{Summary: fmt.Sprintf("%s 버전을 %s로 변경", req.Component.Name, req.Target)}, nil
}

func bumpPom(content, group, artifact, from, to string) (string, error) {
	for _, loc := range dependencyBlock.FindAllStringIndex(content, -1) {
		block := content[loc[0]:loc[1]]
		if !strings.Contains(block, "<artifactId>"+artifact+"</artifactId>") || !strings.Contains(block, "<groupId>"+group+"</groupId>") {
			continue
		}
		m := versionTag.FindStringSubmatchIndex(block)
		if m == nil {
			break
		}
		v := block[m[2]:m[3]]
		if prop, ok := strings.CutPrefix(v, "${"); ok {
			prop = strings.TrimSuffix(prop, "}")
			re := regexp.MustCompile(`<` + regexp.QuoteMeta(prop) + `>\s*` + regexp.QuoteMeta(from) + `\s*</` + regexp.QuoteMeta(prop) + `>`)
			if !re.MatchString(content) {
				return "", fmt.Errorf("property %s not defined in this pom: %w", prop, ErrManual)
			}
			return re.ReplaceAllString(content, "<"+prop+">"+to+"</"+prop+">"), nil
		}
		newBlock := block[:m[2]] + to + block[m[3]:]
		return content[:loc[0]] + newBlock + content[loc[1]:], nil
	}
	// Not declared: pin the transitive version through dependencyManagement.
	entry := fmt.Sprintf("\n      <dependency>\n        <groupId>%s</groupId>\n        <artifactId>%s</artifactId>\n        <version>%s</version>\n      </dependency>", group, artifact, to)
	if i := strings.Index(content, "<dependencyManagement>"); i >= 0 {
		j := strings.Index(content[i:], "<dependencies>")
		if j < 0 {
			return "", ErrManual
		}
		at := i + j + len("<dependencies>")
		return content[:at] + entry + content[at:], nil
	}
	i := strings.Index(content, "<dependencies>")
	if i < 0 {
		return "", ErrManual
	}
	block := "<dependencyManagement>\n    <dependencies>" + entry + "\n    </dependencies>\n  </dependencyManagement>\n  "
	return content[:i] + block + content[i:], nil
}

func bumpGradle(req *Request, p *inventory.Project, content, group, artifact, from, to string) (string, error) {
	if p.Lockfile != "" {
		return "", fmt.Errorf("gradle.lockfile must be regenerated with Gradle: %w", ErrManual)
	}
	literal := group + ":" + artifact + ":" + from
	if strings.Contains(content, literal) {
		return strings.ReplaceAll(content, literal, group+":"+artifact+":"+to), nil
	}
	catalog := path.Join(p.Dir, "gradle/libs.versions.toml")
	cat, err := req.read(catalog)
	if err != nil {
		return "", ErrManual
	}
	// Version references: replace the [versions] entry holding the old value
	// only when a library entry for this module references it.
	if !strings.Contains(cat, group+":"+artifact) && !strings.Contains(cat, `"`+artifact+`"`) {
		return "", ErrManual
	}
	updated := strings.Replace(cat, `"`+from+`"`, `"`+to+`"`, 1)
	if updated == cat {
		return "", ErrManual
	}
	if err := req.write(catalog, updated); err != nil {
		return "", err
	}
	return content, nil
}

// ---------------------------------------------------------------------------
// Cargo
// ---------------------------------------------------------------------------

type cargoFixer struct{}

func (cargoFixer) Fix(ctx context.Context, req *Request) (Result, error) {
	var logs []string
	for _, p := range req.Projects {
		script := fmt.Sprintf("cargo update -p %s --precise %s", shellQuote(req.Component.Name+"@"+req.Component.Version), shellQuote(req.Target))
		out, err := req.exec(ctx, ToolchainRust, dir(p), script)
		logs = append(logs, "$ "+script, out)
		if err != nil {
			return Result{Log: strings.Join(logs, "\n")}, err
		}
	}
	return Result{Summary: fmt.Sprintf("`cargo update -p %s --precise %s`", req.Component.Name, req.Target), Log: strings.Join(logs, "\n")}, nil
}

// ---------------------------------------------------------------------------
// Container images
// ---------------------------------------------------------------------------

type imageFixer struct{}

// Fix rewrites every reference to the images running the component, keeping
// tag suffixes such as "-alpine".
func (imageFixer) Fix(ctx context.Context, req *Request) (Result, error) {
	var changed []string
	for _, img := range req.Images {
		ref := img.Image
		newTag := ReplaceTagVersion(ref.Tag, req.Target)
		if newTag == "" {
			return Result{}, fmt.Errorf("image %s has no version tag to bump: %w", container.String(ref), ErrManual)
		}
		newRef := *ref
		newRef.Tag = newTag
		newRef.Digest = ""
		if req.TagExists != nil && !req.TagExists(ctx, container.String(&newRef)) {
			// The suffixed variant may not exist for this release.
			plain := newRef
			plain.Tag = req.Target
			if !req.TagExists(ctx, container.String(&plain)) {
				return Result{}, fmt.Errorf("neither %s nor %s exists in the registry", container.String(&newRef), container.String(&plain))
			}
			newRef = plain
		}
		for _, loc := range img.Locations {
			content, err := req.read(loc)
			if err != nil {
				return Result{}, err
			}
			updated := replaceImageRef(content, ref, &newRef)
			if updated == content {
				// FROM image:${VERSION}: bump the ARG default instead.
				updated = replaceArgDefault(content, container.VersionFromTag(ref.Tag), req.Target)
			}
			if updated == content {
				continue
			}
			if err := req.write(loc, updated); err != nil {
				return Result{}, err
			}
			changed = append(changed, fmt.Sprintf("%s: %s → %s", loc, container.String(ref), container.String(&newRef)))
		}
	}
	if len(changed) == 0 {
		return Result{}, fmt.Errorf("no image reference could be rewritten: %w", ErrManual)
	}
	return Result{Summary: "베이스 이미지 태그 변경: " + strings.Join(changed, "; ")}, nil
}

// ReplaceTagVersion swaps the leading version of a tag: "1.25.3-alpine" with
// target "1.27.1" becomes "1.27.1-alpine".
func ReplaceTagVersion(tag, target string) string {
	v := container.VersionFromTag(tag)
	if v == "" {
		return ""
	}
	i := strings.Index(tag, v)
	return tag[:i] + target + tag[i+len(v):]
}

// replaceImageRef rewrites occurrences of an image reference, written with
// or without the implicit "library/" prefix.
func replaceImageRef(content string, from, to *inventory.ImageRef) string {
	repo := strings.TrimPrefix(from.Repository, "library/")
	if from.Registry != "" {
		repo = from.Registry + "/" + from.Repository
	}
	pattern := `(^|[\s"'=])((?:docker\.io/)?(?:library/)?` + regexp.QuoteMeta(repo) + `):` + regexp.QuoteMeta(from.Tag) + `(@sha256:[0-9a-f]+)?\b`
	re := regexp.MustCompile(`(?m)` + pattern)
	return re.ReplaceAllString(content, "${1}${2}:"+to.Tag)
}

// replaceArgDefault rewrites Dockerfile "ARG NAME=<version>" defaults.
func replaceArgDefault(content, from, to string) string {
	if from == "" {
		return content
	}
	re := regexp.MustCompile(`(?mi)^(\s*ARG\s+[A-Za-z_][A-Za-z0-9_]*=["']?)` + regexp.QuoteMeta(from) + `(["']?\s*)$`)
	return re.ReplaceAllString(content, "${1}"+to+"${2}")
}

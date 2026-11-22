// Package runner executes build and test commands of untrusted repositories.
// The Docker runner is the default: commands run in a throwaway toolchain
// container with resource limits, as the invoking user, with only the
// working copy mounted. The local runner exists for environments without
// Docker and must be enabled explicitly.
package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Spec describes one command.
type Spec struct {
	// Image is the toolchain image (Docker runner only).
	Image string
	// Root is the host directory mounted as /workspace.
	Root string
	// WorkDir is relative to Root.
	WorkDir string
	// Script runs with sh -c.
	Script  string
	Env     []string
	Timeout time.Duration
}

// Result is the outcome of a command. A non-zero exit code is not an error.
type Result struct {
	ExitCode int
	Output   string
	Duration time.Duration
}

// Runner runs commands. err is reserved for failures to run at all.
type Runner interface {
	Run(ctx context.Context, spec Spec) (Result, error)
	// Describe names the execution environment for test reports.
	Describe(spec Spec) string
}

// MaxOutput is how much trailing output is kept.
const MaxOutput = 32 << 10

// Tail keeps the last MaxOutput bytes of s.
func Tail(s string) string {
	if len(s) <= MaxOutput {
		return s
	}
	return "…(truncated)…\n" + s[len(s)-MaxOutput:]
}

// Docker runs commands in containers.
type Docker struct {
	Binary    string
	Memory    string
	CPUs      string
	PidsLimit int

	pulled sync.Map // image -> struct{}
}

// NewDocker returns a Docker runner with conservative limits.
func NewDocker() *Docker {
	return &Docker{Binary: "docker", Memory: "4g", CPUs: "2", PidsLimit: 2048}
}

// Describe implements Runner.
func (d *Docker) Describe(spec Spec) string {
	return fmt.Sprintf("Docker 격리 컨테이너 (`%s`, 메모리 %s, CPU %s)", spec.Image, d.Memory, d.CPUs)
}

// Run implements Runner.
func (d *Docker) Run(ctx context.Context, spec Spec) (Result, error) {
	if spec.Image == "" {
		return Result{}, errors.New("runner: no toolchain image configured")
	}
	pullLog, err := d.ensureImage(ctx, spec.Image)
	if err != nil {
		return Result{ExitCode: -1, Output: pullLog}, err
	}
	name := "vulngraph-run-" + randomHex(6)
	args := []string{
		"run", "--rm", "--name", name,
		"-v", spec.Root + ":/workspace", "-w", filepath.ToSlash(filepath.Join("/workspace", spec.WorkDir)),
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--memory", d.Memory, "--cpus", d.CPUs, "--pids-limit", fmt.Sprint(d.PidsLimit),
		"--security-opt", "no-new-privileges",
		// Arbitrary UIDs have no home directory; keep every cache in /tmp.
		"-e", "HOME=/tmp", "-e", "GOPATH=/tmp/go", "-e", "GOCACHE=/tmp/.cache/go-build",
		"-e", "GOTOOLCHAIN=auto", "-e", "GOFLAGS=-buildvcs=false", "-e", "npm_config_cache=/tmp/.npm",
		"-e", "PIP_CACHE_DIR=/tmp/.pip", "-e", "CARGO_HOME=/tmp/.cargo", "-e", "MAVEN_OPTS=-Dmaven.repo.local=/tmp/.m2",
		"-e", "GRADLE_USER_HOME=/tmp/.gradle", "-e", "PIP_USER=1", "-e", "PYTHONUSERBASE=/tmp/.local",
		"-e", "PATH=/tmp/.local/bin:/tmp/go/bin:/usr/local/go/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	for _, e := range spec.Env {
		args = append(args, "-e", e)
	}
	args = append(args, spec.Image, "sh", "-c", spec.Script)

	res, err := run(ctx, spec.Timeout, "", nil, d.Binary, args...)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		// The CLI was killed but the container may still run.
		_ = exec.Command(d.Binary, "rm", "-f", name).Run()
	}
	if pullLog != "" {
		res.Output = Tail(pullLog + "\n" + res.Output)
	}
	return res, err
}

// ensureImage pulls an image once, so a slow first pull is visible in the
// step log instead of looking like a hung command.
func (d *Docker) ensureImage(ctx context.Context, image string) (string, error) {
	if _, ok := d.pulled.Load(image); ok {
		return "", nil
	}
	if err := exec.CommandContext(ctx, d.Binary, "image", "inspect", image).Run(); err == nil {
		d.pulled.Store(image, struct{}{})
		return "", nil
	}
	res, err := run(ctx, 20*time.Minute, "", nil, d.Binary, "pull", "-q", image)
	if err == nil && res.ExitCode != 0 {
		err = fmt.Errorf("docker pull %s: exit %d", image, res.ExitCode)
	}
	if err != nil {
		return res.Output, err
	}
	d.pulled.Store(image, struct{}{})
	return "pulled toolchain image " + image, nil
}

// Local runs commands directly on the host.
type Local struct{}

// Describe implements Runner.
func (Local) Describe(Spec) string { return "로컬 호스트 (격리 없음)" }

// Run implements Runner.
func (Local) Run(ctx context.Context, spec Spec) (Result, error) {
	return run(ctx, spec.Timeout, filepath.Join(spec.Root, spec.WorkDir), spec.Env, "sh", "-c", spec.Script)
}

func run(ctx context.Context, timeout time.Duration, dir string, env []string, name string, args ...string) (Result, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	err := cmd.Run()
	res := Result{Output: Tail(out.String()), Duration: time.Since(start)}
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return res, ctx.Err()
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	case err != nil:
		return res, err
	}
	return res, nil
}

// DockerCLI wraps docker commands used for images (build, run, push).
type DockerCLI struct {
	Binary string
}

// Exec runs docker and returns trimmed combined output; a non-zero exit is
// an error carrying the output.
func (d *DockerCLI) Exec(ctx context.Context, args ...string) (string, error) {
	res, err := run(ctx, 0, "", nil, d.binary(), args...)
	out := strings.TrimSpace(res.Output)
	if err != nil {
		return out, err
	}
	if res.ExitCode != 0 {
		return out, fmt.Errorf("docker %s: exit %d: %s", args[0], res.ExitCode, lastLine(out))
	}
	return out, nil
}

func (d *DockerCLI) binary() string {
	if d.Binary == "" {
		return "docker"
	}
	return d.Binary
}

func lastLine(s string) string {
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

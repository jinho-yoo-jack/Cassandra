// Package fixer rewrites manifests and lockfiles so a vulnerable component
// resolves to a fixed version. Edits that need the ecosystem's own resolver
// (go get, npm install, cargo update) run through a runner.Runner.
package fixer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
	"github.com/jinho-yoo-jack/vulngraph/pkg/runner"
)

// ErrManual means no automatic fix exists for this case.
var ErrManual = errors.New("automatic fix is not supported for this manifest; manual remediation required")

// Toolchains maps a toolchain key to a container image.
type Toolchains map[string]string

// Toolchain keys.
const (
	ToolchainGo     = "go"
	ToolchainNode   = "node"
	ToolchainPython = "python"
	ToolchainMaven  = "maven"
	ToolchainGradle = "gradle"
	ToolchainRust   = "rust"
	ToolchainRuby   = "ruby"
	ToolchainPHP    = "php"
)

// DefaultToolchains are used unless overridden by flags.
var DefaultToolchains = Toolchains{
	ToolchainGo: "golang:1.27", ToolchainNode: "node:24", ToolchainPython: "python:3.13",
	ToolchainMaven: "maven:3-eclipse-temurin-21", ToolchainGradle: "gradle:jdk21",
	ToolchainRust: "rust:1", ToolchainRuby: "ruby:3.4", ToolchainPHP: "composer:2",
}

// Request describes one fix.
type Request struct {
	// Root is the working copy on the host.
	Root      string
	Component *inventory.Component
	// Projects are the manifests the component appears in.
	Projects []*inventory.Project
	// Images are container components running the component (image fixes).
	Images []*inventory.Component
	Target string

	Runner     runner.Runner
	Toolchains Toolchains
	// TagExists checks that an image tag can be pulled.
	TagExists func(ctx context.Context, ref string) bool
}

// Result describes what a fix changed.
type Result struct {
	Summary string
	Log     string
}

// Fixer applies a fix for one ecosystem.
type Fixer interface {
	Fix(ctx context.Context, req *Request) (Result, error)
}

// For returns the fixer of a component.
func For(c *inventory.Component) (Fixer, error) {
	switch c.Ecosystem {
	case inventory.Go:
		return goFixer{}, nil
	case inventory.NPM:
		return npmFixer{}, nil
	case inventory.PyPI:
		return pythonFixer{}, nil
	case inventory.Maven:
		return mavenFixer{}, nil
	case inventory.CratesIO:
		return cargoFixer{}, nil
	case inventory.Process, inventory.Image:
		return imageFixer{}, nil
	}
	return nil, fmt.Errorf("%s: %w", c.Ecosystem, ErrManual)
}

// exec runs a script in a project directory and fails on non-zero exit.
func (r *Request) exec(ctx context.Context, toolchain, workDir, script string) (string, error) {
	res, err := r.Runner.Run(ctx, runner.Spec{
		Image: r.Toolchains[toolchain], Root: r.Root, WorkDir: workDir, Script: script, Timeout: 15 * time.Minute,
	})
	if err != nil {
		return res.Output, err
	}
	if res.ExitCode != 0 {
		return res.Output, fmt.Errorf("`%s` exited with %d", script, res.ExitCode)
	}
	return res.Output, nil
}

func (r *Request) path(rel string) string { return filepath.Join(r.Root, filepath.FromSlash(rel)) }

func (r *Request) read(rel string) (string, error) {
	data, err := os.ReadFile(r.path(rel))
	return string(data), err
}

func (r *Request) write(rel, content string) error {
	return os.WriteFile(r.path(rel), []byte(content), 0o644)
}

// shellQuote quotes a single shell argument.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func dir(p *inventory.Project) string {
	if p.Dir == "." {
		return ""
	}
	return path.Clean(p.Dir)
}

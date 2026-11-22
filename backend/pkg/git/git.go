// Package git drives the git CLI for cloning, branching, committing and
// pushing. Credentials are injected through GIT_CONFIG_* environment
// variables scoped to github.com, so tokens never land in argv, remote URLs
// or .git/config.
package git

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Repo is a local working copy.
type Repo struct {
	Dir   string
	token string
}

// Open returns a Repo for an existing working copy.
func Open(dir, token string) *Repo { return &Repo{Dir: dir, token: token} }

// CloneOptions configures Clone.
type CloneOptions struct {
	URL string
	// Ref is a branch, tag or commit; empty selects the default branch.
	Ref   string
	Depth int
	Token string
}

// CloneResult describes what was checked out.
type CloneResult struct {
	// Branch is the checked out branch, empty when Ref was a tag or commit.
	Branch string
	Commit string
}

// Clone fetches a single ref into dir. Fetching by ref works uniformly for
// branches, tags and commit SHAs, unlike git clone --branch.
func Clone(ctx context.Context, dir string, opts CloneOptions) (*Repo, *CloneResult, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	r := Open(dir, opts.Token)
	if _, err := r.Run(ctx, "init", "-q"); err != nil {
		return nil, nil, err
	}
	if _, err := r.Run(ctx, "remote", "add", "origin", opts.URL); err != nil {
		return nil, nil, err
	}
	res := &CloneResult{}
	ref := opts.Ref
	if ref == "" {
		branch, err := r.DefaultBranch(ctx)
		if err != nil {
			return nil, nil, err
		}
		ref, res.Branch = branch, branch
	} else if r.isRemoteBranch(ctx, ref) {
		res.Branch = ref
	}
	args := []string{"fetch", "-q", "--no-tags"}
	if opts.Depth > 0 {
		args = append(args, "--depth", fmt.Sprint(opts.Depth))
	}
	if _, err := r.Run(ctx, append(args, "origin", ref)...); err != nil {
		return nil, nil, err
	}
	checkout := []string{"checkout", "-q", "FETCH_HEAD"}
	if res.Branch != "" {
		checkout = []string{"checkout", "-q", "-B", res.Branch, "FETCH_HEAD"}
	}
	if _, err := r.Run(ctx, checkout...); err != nil {
		return nil, nil, err
	}
	commit, err := r.Run(ctx, "rev-parse", "HEAD")
	if err != nil {
		return nil, nil, err
	}
	res.Commit = commit
	return r, res, nil
}

// DefaultBranch asks the remote for the branch HEAD points to.
func (r *Repo) DefaultBranch(ctx context.Context) (string, error) {
	out, err := r.Run(ctx, "ls-remote", "--symref", "origin", "HEAD")
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "ref: refs/heads/"); ok {
			branch, _, _ := strings.Cut(rest, "\t")
			return branch, nil
		}
	}
	return "", errors.New("remote has no default branch")
}

func (r *Repo) isRemoteBranch(ctx context.Context, ref string) bool {
	out, err := r.Run(ctx, "ls-remote", "--heads", "origin", ref)
	return err == nil && strings.TrimSpace(out) != ""
}

// CreateBranch creates (or resets) a branch at HEAD and checks it out.
func (r *Repo) CreateBranch(ctx context.Context, name string) error {
	_, err := r.Run(ctx, "checkout", "-q", "-B", name)
	return err
}

// ResetHard discards every change, including untracked files, back to rev.
func (r *Repo) ResetHard(ctx context.Context, rev string) error {
	if _, err := r.Run(ctx, "reset", "-q", "--hard", rev); err != nil {
		return err
	}
	_, err := r.Run(ctx, "clean", "-q", "-fdx")
	return err
}

// Signature is a commit author.
type Signature struct {
	Name  string
	Email string
}

// CommitAll stages everything and commits. When there is nothing to commit
// it returns the current HEAD.
func (r *Repo) CommitAll(ctx context.Context, message string, author Signature) (string, error) {
	if _, err := r.Run(ctx, "add", "-A"); err != nil {
		return "", err
	}
	status, err := r.Run(ctx, "status", "--porcelain")
	if err != nil {
		return "", err
	}
	if status != "" {
		if _, err := r.Run(ctx, "-c", "user.name="+author.Name, "-c", "user.email="+author.Email,
			"commit", "-q", "--no-verify", "-m", message); err != nil {
			return "", err
		}
	}
	return r.Run(ctx, "rev-parse", "HEAD")
}

// CommitPaths stages and commits only the given paths.
func (r *Repo) CommitPaths(ctx context.Context, message string, author Signature, paths ...string) (string, error) {
	if _, err := r.Run(ctx, append([]string{"add", "--"}, paths...)...); err != nil {
		return "", err
	}
	staged, err := r.Run(ctx, "diff", "--cached", "--name-only")
	if err != nil {
		return "", err
	}
	if staged != "" {
		if _, err := r.Run(ctx, "-c", "user.name="+author.Name, "-c", "user.email="+author.Email,
			"commit", "-q", "--no-verify", "-m", message); err != nil {
			return "", err
		}
	}
	return r.Run(ctx, "rev-parse", "HEAD")
}

// Diff returns the unified diff between base and the working tree.
func (r *Repo) Diff(ctx context.Context, base string) (string, error) {
	return r.Run(ctx, "diff", "--no-color", base)
}

// ChangedFiles lists files that differ from base.
func (r *Repo) ChangedFiles(ctx context.Context, base string) ([]string, error) {
	out, err := r.Run(ctx, "diff", "--name-only", base)
	if err != nil || out == "" {
		return nil, err
	}
	return strings.Split(out, "\n"), nil
}

// Push force-pushes HEAD to a branch owned by vulngraph.
func (r *Repo) Push(ctx context.Context, branch string) error {
	_, err := r.Run(ctx, "push", "-q", "--force", "origin", "HEAD:refs/heads/"+branch)
	return err
}

// Run executes git in the working copy and returns trimmed stdout.
func (r *Repo) Run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.Dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=true", "LC_ALL=C")
	if r.token != "" {
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + r.token))
		cmd.Env = append(cmd.Env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
			"GIT_CONFIG_VALUE_0=AUTHORIZATION: basic "+basic,
		)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// Package github parses repository URLs, creates pull requests and verifies
// webhook signatures.
package github

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/util/httpjson"
)

// RepoRef identifies a repository.
type RepoRef struct {
	Owner string
	Name  string
	// Ref is the branch or tag from a /tree/<ref> URL, if any.
	Ref string
}

// CloneURL is the HTTPS clone URL.
func (r RepoRef) CloneURL() string {
	return fmt.Sprintf("https://github.com/%s/%s.git", r.Owner, r.Name)
}

// HTMLURL is the web URL.
func (r RepoRef) HTMLURL() string { return fmt.Sprintf("https://github.com/%s/%s", r.Owner, r.Name) }

var (
	ownerRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// ParseRepoURL accepts https://github.com/o/r(.git), github.com/o/r,
// git@github.com:o/r.git, o/r and .../tree/<ref>.
func ParseRepoURL(s string) (RepoRef, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "git@github.com:")
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		if !strings.EqualFold(u.Host, "github.com") && !strings.EqualFold(u.Host, "www.github.com") {
			return RepoRef{}, fmt.Errorf("only github.com repositories are supported, got host %q", u.Host)
		}
		s = u.Path
	}
	s = strings.TrimPrefix(s, "github.com/")
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) < 2 {
		return RepoRef{}, fmt.Errorf("expected owner/repository, got %q", s)
	}
	ref := RepoRef{Owner: parts[0], Name: strings.TrimSuffix(parts[1], ".git")}
	if len(parts) > 3 && parts[2] == "tree" {
		ref.Ref = strings.Join(parts[3:], "/")
	}
	if !ownerRe.MatchString(ref.Owner) || !nameRe.MatchString(ref.Name) || ref.Name == "." || ref.Name == ".." {
		return RepoRef{}, fmt.Errorf("invalid repository %s/%s", ref.Owner, ref.Name)
	}
	return ref, nil
}

// Client calls the GitHub REST API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewClient returns a client for api.github.com.
func NewClient(token string) *Client {
	return &Client{BaseURL: "https://api.github.com", Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// NewPullRequest is the body of a create pull request call.
type NewPullRequest struct {
	Title string `json:"title"`
	Head  string `json:"head"`
	Base  string `json:"base"`
	Body  string `json:"body"`
	Draft bool   `json:"draft"`
}

// PullRequest is the subset of the response that is used.
type PullRequest struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

// CreatePullRequest opens a pull request.
func (c *Client) CreatePullRequest(ctx context.Context, repo RepoRef, pr NewPullRequest) (*PullRequest, error) {
	if c.Token == "" {
		return nil, fmt.Errorf("GitHub token is not configured (--github-token or GITHUB_TOKEN)")
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.Token)
	header.Set("X-GitHub-Api-Version", "2022-11-28")
	var out PullRequest
	u := fmt.Sprintf("%s/repos/%s/%s/pulls", c.BaseURL, repo.Owner, repo.Name)
	if err := httpjson.Do(ctx, c.HTTP, http.MethodPost, u, header, pr, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ValidSignature checks an X-Hub-Signature-256 header in constant time.
func ValidSignature(secret, body []byte, header string) bool {
	sig, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	want, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

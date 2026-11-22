package feeds

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	apierrors "github.com/jinho-yoo-jack/vulngraph/pkg/api/errors"
	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/endpoints/handlers"
	"github.com/jinho-yoo-jack/vulngraph/pkg/github"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/osv"
)

// GitHubWebhookFeed is the Feed name of the push source.
const GitHubWebhookFeed = "github-advisories"

// githubEcosystems maps GitHub advisory ecosystems to OSV names.
var githubEcosystems = map[string]string{
	"go": "Go", "npm": "npm", "pip": "PyPI", "maven": "Maven", "rubygems": "RubyGems",
	"composer": "Packagist", "rust": "crates.io", "nuget": "NuGet", "pub": "Pub", "swift": "SwiftURL",
}

// GitHubWebhook receives security_advisory events from a GitHub App and
// turns them into Changes immediately, closing the gap between polls.
type GitHubWebhook struct {
	Secret []byte
	OSV    *osv.Client
	Cache  *vulndb.Cache
	Syncer *Syncer
	Log    *slog.Logger
}

// WebhookSource registers the push feed so it shows up in the feed list.
type WebhookSource struct{}

func (WebhookSource) Name() string            { return GitHubWebhookFeed }
func (WebhookSource) Mode() string            { return "push" }
func (WebhookSource) Interval() time.Duration { return 0 }
func (WebhookSource) Sync(context.Context, *v1alpha1.FeedStatus) (Changes, error) {
	return Changes{}, nil
}

type securityAdvisoryEvent struct {
	Action           string `json:"action"`
	SecurityAdvisory struct {
		GHSAID          string `json:"ghsa_id"`
		CVEID           string `json:"cve_id"`
		Vulnerabilities []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
		} `json:"vulnerabilities"`
	} `json:"security_advisory"`
}

const maxWebhookBody = 5 << 20

func (h *GitHubWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody))
	if err != nil {
		handlers.ErrorNegotiated(w, r, apierrors.NewBadRequest("cannot read body"))
		return
	}
	if !github.ValidSignature(h.Secret, body, r.Header.Get("X-Hub-Signature-256")) {
		handlers.ErrorNegotiated(w, r, apierrors.NewUnauthorized("invalid webhook signature"))
		return
	}
	switch r.Header.Get("X-GitHub-Event") {
	case "ping":
		w.WriteHeader(http.StatusNoContent)
		return
	case "security_advisory":
	default:
		w.WriteHeader(http.StatusAccepted) // other events are ignored
		return
	}
	var ev securityAdvisoryEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		handlers.ErrorNegotiated(w, r, apierrors.NewBadRequest("invalid payload: "+err.Error()))
		return
	}

	ctx := r.Context()
	adv := ev.SecurityAdvisory
	var changes Changes
	for _, v := range adv.Vulnerabilities {
		if eco, ok := githubEcosystems[v.Package.Ecosystem]; ok {
			changes.Packages = append(changes.Packages, NewPackageKey(eco, v.Package.Name))
		}
	}
	if adv.CVEID != "" {
		changes.CVEs = append(changes.CVEs, adv.CVEID)
	}
	// Refresh the cached record; OSV may lag the webhook by minutes, in
	// which case the next OSV feed run picks the advisory up.
	if o, err := h.OSV.Get(ctx, adv.GHSAID); err == nil {
		_ = h.Cache.Put(vulndb.FromOSV(o))
	}

	status, err := h.Syncer.Status(ctx, GitHubWebhookFeed)
	if err != nil {
		h.Log.Error("[feeds] Webhook feed status unavailable", "err", err)
	}
	status.Processed++
	h.Syncer.Record(ctx, GitHubWebhookFeed, status, changes, nil)
	h.Log.Info("[feeds] Advisory webhook", "action", ev.Action, "ghsa", adv.GHSAID, "cve", adv.CVEID, "packages", len(changes.Packages))
	w.WriteHeader(http.StatusAccepted)
}

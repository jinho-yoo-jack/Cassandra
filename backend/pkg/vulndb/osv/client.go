// Package osv is a client for the OSV.dev API and its GCS data exports.
package osv

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/util/httpjson"
)

const (
	DefaultAPIURL    = "https://api.osv.dev"
	DefaultExportURL = "https://storage.googleapis.com/osv-vulnerabilities"
	// maxBatch is the documented querybatch limit.
	maxBatch = 1000
)

// Client talks to OSV.
type Client struct {
	APIURL    string
	ExportURL string
	HTTP      *http.Client
}

// NewClient returns a client for the public OSV service.
func NewClient() *Client {
	return &Client{APIURL: DefaultAPIURL, ExportURL: DefaultExportURL, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Package identifies a package in an ecosystem.
type Package struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

// Query asks for the vulnerabilities of one package version.
type Query struct {
	Package   Package `json:"package"`
	Version   string  `json:"version,omitempty"`
	PageToken string  `json:"page_token,omitempty"`
}

// VulnRef is a vulnerability id returned by querybatch.
type VulnRef struct {
	ID       string    `json:"id"`
	Modified time.Time `json:"modified"`
}

type batchResponse struct {
	Results []struct {
		Vulns         []VulnRef `json:"vulns"`
		NextPageToken string    `json:"next_page_token"`
	} `json:"results"`
}

// QueryBatch returns, for each query, the ids of the vulnerabilities that
// affect it. Pagination of individual queries is followed transparently.
func (c *Client) QueryBatch(ctx context.Context, queries []Query) ([][]VulnRef, error) {
	out := make([][]VulnRef, len(queries))
	pending := make([]int, len(queries))
	for i := range queries {
		pending[i] = i
	}
	pages := make([]Query, len(queries))
	copy(pages, queries)

	for len(pending) > 0 {
		var next []int
		for start := 0; start < len(pending); start += maxBatch {
			chunk := pending[start:min(start+maxBatch, len(pending))]
			req := struct {
				Queries []Query `json:"queries"`
			}{}
			for _, i := range chunk {
				req.Queries = append(req.Queries, pages[i])
			}
			var resp batchResponse
			if err := httpjson.Do(ctx, c.HTTP, http.MethodPost, c.APIURL+"/v1/querybatch", nil, req, &resp); err != nil {
				return nil, fmt.Errorf("osv querybatch: %w", err)
			}
			if len(resp.Results) != len(chunk) {
				return nil, fmt.Errorf("osv querybatch: got %d results for %d queries", len(resp.Results), len(chunk))
			}
			for j, i := range chunk {
				out[i] = append(out[i], resp.Results[j].Vulns...)
				if tok := resp.Results[j].NextPageToken; tok != "" {
					pages[i].PageToken = tok
					next = append(next, i)
				}
			}
		}
		pending = next
	}
	return out, nil
}

// Get fetches one vulnerability record.
func (c *Client) Get(ctx context.Context, id string) (*Vulnerability, error) {
	var v Vulnerability
	if err := httpjson.Get(ctx, c.HTTP, c.APIURL+"/v1/vulns/"+url.PathEscape(id), nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// ModifiedEntry is one row of modified_id.csv.
type ModifiedEntry struct {
	Modified time.Time
	ID       string
}

// ModifiedSince streams <ecosystem>/modified_id.csv, which is sorted newest
// first, and returns the entries modified strictly after since, newest
// first. Reading stops at the first older row, so only the new head of the
// file is downloaded.
func (c *Client) ModifiedSince(ctx context.Context, ecosystem string, since time.Time) ([]ModifiedEntry, error) {
	u := fmt.Sprintf("%s/%s/modified_id.csv", c.ExportURL, url.PathEscape(ecosystem))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpjson.StatusError{URL: u, Code: resp.StatusCode}
	}
	var out []ModifiedEntry
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		ts, id, ok := strings.Cut(sc.Text(), ",")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		if !t.After(since) {
			break
		}
		// The all-ecosystem file prefixes ids with "<ecosystem>/".
		if i := strings.LastIndexByte(id, '/'); i >= 0 {
			id = id[i+1:]
		}
		out = append(out, ModifiedEntry{Modified: t, ID: id})
	}
	return out, sc.Err()
}

// Vulnerability is an OSV schema record.
type Vulnerability struct {
	ID               string           `json:"id"`
	Modified         time.Time        `json:"modified"`
	Published        time.Time        `json:"published"`
	Withdrawn        *time.Time       `json:"withdrawn,omitempty"`
	Aliases          []string         `json:"aliases"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Severity         []Severity       `json:"severity"`
	Affected         []Affected       `json:"affected"`
	References       []Reference      `json:"references"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
}

// Severity is a CVSS vector.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected lists the affected versions of one package.
type Affected struct {
	Package  Package    `json:"package"`
	Ranges   []Range    `json:"ranges"`
	Versions []string   `json:"versions"`
	Severity []Severity `json:"severity"`
}

// Range is an OSV range of events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one introduced/fixed/last_affected boundary.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference is a link.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// DatabaseSpecific holds the GHSA fields OSV passes through.
type DatabaseSpecific struct {
	Severity string   `json:"severity"`
	CWEIDs   []string `json:"cwe_ids"`
}

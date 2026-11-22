// Package nvd is a rate limited client for the NVD CVE API 2.0.
package nvd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/time/rate"

	"github.com/jinho-yoo-jack/vulngraph/pkg/util/httpjson"
)

// DefaultURL is the CVE API endpoint.
const DefaultURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// MaxRange is the longest lastMod window NVD accepts.
const MaxRange = 120 * 24 * time.Hour

// Client queries NVD within its published rate limits: 5 requests per 30
// seconds without an API key and 50 with one.
type Client struct {
	URL     string
	APIKey  string
	HTTP    *http.Client
	limiter *rate.Limiter
}

// NewClient returns a client; apiKey may be empty.
func NewClient(apiKey string) *Client {
	limit := rate.Every(30 * time.Second / 5)
	if apiKey != "" {
		limit = rate.Every(30 * time.Second / 50)
	}
	return &Client{URL: DefaultURL, APIKey: apiKey, HTTP: &http.Client{Timeout: 60 * time.Second}, limiter: rate.NewLimiter(limit, 1)}
}

type response struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE CVE `json:"cve"`
	} `json:"vulnerabilities"`
}

// CVE is the subset of an NVD CVE record that is used.
type CVE struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	VulnStatus     string          `json:"vulnStatus"`
	Descriptions   []LangString    `json:"descriptions"`
	Metrics        Metrics         `json:"metrics"`
	Weaknesses     []Weakness      `json:"weaknesses"`
	Configurations []Configuration `json:"configurations"`
	References     []Reference     `json:"references"`
}

// LangString is a localised string.
type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metrics holds CVSS metrics by version.
type Metrics struct {
	V40 []Metric `json:"cvssMetricV40"`
	V31 []Metric `json:"cvssMetricV31"`
	V30 []Metric `json:"cvssMetricV30"`
	V2  []Metric `json:"cvssMetricV2"`
}

// Metric is one CVSS assessment. CVSS v2 metrics carry the qualitative
// rating outside cvssData.
type Metric struct {
	Source       string `json:"source"`
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// Weakness lists CWEs.
type Weakness struct {
	Description []LangString `json:"description"`
}

// Configuration is an applicability statement.
type Configuration struct {
	Nodes []struct {
		Operator string     `json:"operator"`
		Negate   bool       `json:"negate"`
		CPEMatch []CPEMatch `json:"cpeMatch"`
	} `json:"nodes"`
}

// CPEMatch is one CPE match criterion.
type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// Reference is a link.
type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// CPEName builds a full CPE 2.3 application name from "vendor:product".
func CPEName(vendorProduct, version string) string {
	return fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*", vendorProduct, version)
}

// CVEsByCPE returns CVEs for which the given CPE name is vulnerable.
func (c *Client) CVEsByCPE(ctx context.Context, cpeName string) ([]CVE, error) {
	// isVulnerable is a flag without value; url.Values would append "=".
	return c.paginate(ctx, "cpeName="+url.QueryEscape(cpeName)+"&isVulnerable", nil)
}

// CVE returns a single record.
func (c *Client) CVE(ctx context.Context, id string) (*CVE, error) {
	cves, err := c.paginate(ctx, "cveId="+url.QueryEscape(id), nil)
	if err != nil {
		return nil, err
	}
	if len(cves) == 0 {
		return nil, &httpjson.StatusError{URL: c.URL, Code: http.StatusNotFound, Body: id + " not found"}
	}
	return &cves[0], nil
}

// ModifiedBetween calls fn for every CVE modified within [start, end], which
// must not span more than MaxRange.
func (c *Client) ModifiedBetween(ctx context.Context, start, end time.Time, fn func(CVE) error) error {
	q := url.Values{}
	q.Set("lastModStartDate", formatTime(start))
	q.Set("lastModEndDate", formatTime(end))
	_, err := c.paginate(ctx, q.Encode(), fn)
	return err
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000") + "+00:00"
}

// paginate follows startIndex until every result is read. When fn is set the
// results are streamed to it instead of being collected.
func (c *Client) paginate(ctx context.Context, query string, fn func(CVE) error) ([]CVE, error) {
	var (
		out   []CVE
		start int
	)
	header := http.Header{}
	if c.APIKey != "" {
		header.Set("apiKey", c.APIKey)
	}
	for {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		var resp response
		u := c.URL + "?" + query + "&resultsPerPage=2000&startIndex=" + strconv.Itoa(start)
		if err := httpjson.Get(ctx, c.HTTP, u, header, &resp); err != nil {
			return nil, fmt.Errorf("nvd: %w", err)
		}
		for _, v := range resp.Vulnerabilities {
			if fn != nil {
				if err := fn(v.CVE); err != nil {
					return nil, err
				}
				continue
			}
			out = append(out, v.CVE)
		}
		start += len(resp.Vulnerabilities)
		if len(resp.Vulnerabilities) == 0 || start >= resp.TotalResults {
			return out, nil
		}
	}
}

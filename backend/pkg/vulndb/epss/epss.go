// Package epss queries FIRST EPSS scores with a daily cache.
package epss

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/util/httpjson"
)

// DefaultURL is the EPSS API.
const DefaultURL = "https://api.first.org/data/v1/epss"

// chunkSize keeps the query string well under URL length limits.
const chunkSize = 50

// Client fetches EPSS scores. Scores change once a day, so results are
// cached for TTL.
type Client struct {
	URL  string
	HTTP *http.Client
	TTL  time.Duration

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	score   *v1alpha1.EPSS
	fetched time.Time
}

// NewClient returns a client.
func NewClient() *Client {
	return &Client{URL: DefaultURL, HTTP: &http.Client{Timeout: 30 * time.Second}, TTL: 24 * time.Hour, cache: map[string]cached{}}
}

// Scores returns the scores of the given CVEs. CVEs without a score are
// omitted.
func (c *Client) Scores(ctx context.Context, cves []string) (map[string]*v1alpha1.EPSS, error) {
	out := map[string]*v1alpha1.EPSS{}
	var missing []string
	now := time.Now()
	c.mu.Lock()
	for _, id := range cves {
		if e, ok := c.cache[id]; ok && now.Sub(e.fetched) < c.TTL {
			if e.score != nil {
				out[id] = e.score
			}
			continue
		}
		missing = append(missing, id)
	}
	c.mu.Unlock()

	for start := 0; start < len(missing); start += chunkSize {
		chunk := missing[start:min(start+chunkSize, len(missing))]
		var resp struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
				Date       string `json:"date"`
			} `json:"data"`
		}
		if err := httpjson.Get(ctx, c.HTTP, c.URL+"?cve="+url.QueryEscape(strings.Join(chunk, ",")), nil, &resp); err != nil {
			return out, err
		}
		c.mu.Lock()
		for _, id := range chunk {
			c.cache[id] = cached{fetched: now} // remember misses too
		}
		for _, d := range resp.Data {
			score, _ := strconv.ParseFloat(d.EPSS, 64)
			pct, _ := strconv.ParseFloat(d.Percentile, 64)
			e := &v1alpha1.EPSS{Score: score, Percentile: pct, Date: d.Date}
			c.cache[d.CVE] = cached{score: e, fetched: now}
			out[d.CVE] = e
		}
		c.mu.Unlock()
	}
	return out, nil
}

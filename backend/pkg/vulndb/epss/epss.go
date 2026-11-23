// Package epss queries FIRST EPSS scores with a daily cache.
package epss

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/util/httpjson"
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
		if resp.Data == nil {
			return out, fmt.Errorf("epss: missing data array")
		}
		// Validate a whole response before caching either scores or misses.
		validated := make(map[string]*v1alpha1.EPSS, len(resp.Data))
		for _, d := range resp.Data {
			if strings.TrimSpace(d.CVE) == "" {
				return out, fmt.Errorf("epss: missing CVE ID")
			}
			score, err := probability(d.EPSS)
			if err != nil {
				return out, fmt.Errorf("epss: %s score: %w", d.CVE, err)
			}
			pct, err := probability(d.Percentile)
			if err != nil {
				return out, fmt.Errorf("epss: %s percentile: %w", d.CVE, err)
			}
			validated[d.CVE] = &v1alpha1.EPSS{Score: score, Percentile: pct, Date: d.Date}
		}
		c.mu.Lock()
		for _, id := range chunk {
			c.cache[id] = cached{fetched: now} // remember misses too
		}
		for id, e := range validated {
			c.cache[id] = cached{score: e, fetched: now}
			out[id] = e
		}
		c.mu.Unlock()
	}
	return out, nil
}

func probability(raw string) (float64, error) {
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(v) || v < 0 || v > 1 {
		return 0, fmt.Errorf("invalid probability %q", raw)
	}
	return v, nil
}

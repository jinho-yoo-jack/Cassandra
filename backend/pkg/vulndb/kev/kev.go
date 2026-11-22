// Package kev loads the CISA Known Exploited Vulnerabilities catalog.
package kev

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/util/httpjson"
)

// DefaultURL is the catalog feed.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// Catalog is an in-memory copy of the KEV catalog.
type Catalog struct {
	URL  string
	HTTP *http.Client

	mu      sync.RWMutex
	entries map[string]v1alpha1.KEV
	version string
}

// NewCatalog returns an empty catalog; call Refresh to load it.
func NewCatalog() *Catalog {
	return &Catalog{URL: DefaultURL, HTTP: &http.Client{Timeout: 60 * time.Second}, entries: map[string]v1alpha1.KEV{}}
}

type feed struct {
	CatalogVersion  string `json:"catalogVersion"`
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		RequiredAction             string `json:"requiredAction"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// Refresh downloads the catalog and returns the CVEs that were not in the
// previous copy.
func (c *Catalog) Refresh(ctx context.Context) (added []string, version string, err error) {
	var f feed
	if err := httpjson.Get(ctx, c.HTTP, c.URL, nil, &f); err != nil {
		return nil, "", err
	}
	entries := make(map[string]v1alpha1.KEV, len(f.Vulnerabilities))
	for _, v := range f.Vulnerabilities {
		entries[v.CVEID] = v1alpha1.KEV{
			DateAdded: v.DateAdded, DueDate: v.DueDate, RequiredAction: v.RequiredAction,
			KnownRansomware: v.KnownRansomwareCampaignUse == "Known",
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 0 {
		for id := range entries {
			if _, ok := c.entries[id]; !ok {
				added = append(added, id)
			}
		}
	}
	c.entries, c.version = entries, f.CatalogVersion
	return added, f.CatalogVersion, nil
}

// Lookup returns the KEV entry of a CVE.
func (c *Catalog) Lookup(cve string) (*v1alpha1.KEV, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[cve]
	if !ok {
		return nil, false
	}
	return &e, true
}

// Len returns the number of entries.
func (c *Catalog) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

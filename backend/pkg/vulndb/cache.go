package vulndb

import (
	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/storage/boltstore"
)

// Cache persists normalised advisories so that rescans and the
// vulnerabilities API do not refetch unchanged records.
type Cache struct {
	blobs *boltstore.Blobs
}

// NewCache returns a cache stored in blobs.
func NewCache(blobs *boltstore.Blobs) *Cache { return &Cache{blobs: blobs} }

// Get returns a cached advisory.
func (c *Cache) Get(id string) (*v1alpha1.Vulnerability, bool) {
	var v v1alpha1.Vulnerability
	if err := c.blobs.Get(id, &v); err != nil {
		return nil, false
	}
	return &v, true
}

// Put stores an advisory under its ID and its CVE alias, so lookups by CVE
// work for GHSA/GO/PYSEC records.
func (c *Cache) Put(v *v1alpha1.Vulnerability) error {
	if err := c.blobs.Put(v.ID, v); err != nil {
		return err
	}
	if v.CVE != "" && v.CVE != v.ID {
		if _, ok := c.Get(v.CVE); !ok {
			return c.blobs.Put(v.CVE, v)
		}
	}
	return nil
}

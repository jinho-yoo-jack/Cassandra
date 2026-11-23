package vulndb

import (
	"encoding/json"
	"sync"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
)

// MemoryCache is a concurrent, process-local advisory cache. Like the Bolt
// adapter, it stores JSON snapshots so inputs and returned records never share
// mutable slices or pointers with stored records. Its zero value is usable.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string][]byte
}

// NewMemoryCache returns an empty cache without opening a database.
func NewMemoryCache() *MemoryCache { return &MemoryCache{} }

func (c *MemoryCache) Get(id string) (*v1alpha1.Vulnerability, bool) {
	c.mu.RLock()
	data, ok := c.entries[id]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	var v v1alpha1.Vulnerability
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, false
	}
	return &v, true
}

func (c *MemoryCache) Put(v *v1alpha1.Vulnerability) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string][]byte)
	}
	c.entries[v.ID] = data
	if v.CVE != "" && v.CVE != v.ID {
		if _, ok := c.entries[v.CVE]; !ok {
			c.entries[v.CVE] = data
		}
	}
	return nil
}

var _ AdvisoryCache = (*MemoryCache)(nil)
var _ AdvisoryCache = (*Cache)(nil)

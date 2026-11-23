package vulndb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/util/httpjson"
)

// Lookup returns an enriched advisory, reading the raw cache before OSV and
// falling back to NVD only for CVE IDs absent from OSV. Ordinary EPSS failures
// are logged rather than hiding an otherwise available advisory.
func (m *Matcher) Lookup(ctx context.Context, id string) (*v1alpha1.Vulnerability, error) {
	v, err := m.lookupRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := m.Enrich(ctx, map[string]*v1alpha1.Vulnerability{id: v}); err != nil {
		if cancelErr := cancellationError(ctx); cancelErr != nil {
			return nil, cancelErr
		}
		m.Log.Warn("[vulnerability] EPSS lookup failed", "id", id, "err", err)
	}
	return v, nil
}

func (m *Matcher) lookupRaw(ctx context.Context, id string) (*v1alpha1.Vulnerability, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v, ok := m.Cache.Get(id); ok {
		return v, nil
	}
	o, err := m.OSV.Get(ctx, id)
	if cancelErr := cancellationError(ctx); cancelErr != nil {
		return nil, cancelErr
	}
	if err == nil {
		if o == nil || o.ID == "" {
			return nil, fmt.Errorf("OSV advisory %s: missing record or ID", id)
		}
		v := FromOSV(o)
		_ = m.Cache.Put(v)
		return v, nil
	}
	var status *httpjson.StatusError
	if !strings.HasPrefix(id, "CVE-") || !errors.As(err, &status) || status.Code != http.StatusNotFound {
		return nil, err
	}
	c, err := m.NVD.CVE(ctx, id)
	if cancelErr := cancellationError(ctx); cancelErr != nil {
		return nil, cancelErr
	}
	if err != nil {
		return nil, err
	}
	if c == nil || c.ID == "" {
		return nil, fmt.Errorf("NVD advisory %s: missing record or ID", id)
	}
	v := FromNVD(c)
	_ = m.Cache.Put(v)
	return v, nil
}

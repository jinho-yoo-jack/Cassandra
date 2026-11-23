// Package bootstrap assembles scan-only collaborators shared by the server and
// CLI. Constructors do not perform IO; lifecycle work is explicit in Prepare.
package bootstrap

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory/extractor/all"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/epss"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/kev"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

type ScanOptions struct {
	NVDAPIKey                       string
	GoProxy                         string
	OSVURL, NVDURL, KEVURL, EPSSURL string
}

type ScanRuntime struct {
	OSV        *osv.Client
	NVD        *nvd.Client
	KEV        *kev.Catalog
	EPSS       *epss.Client
	Extractors []inventory.Extractor
}

func NewScan(opts ScanOptions) *ScanRuntime {
	r := &ScanRuntime{
		OSV: osv.NewClient(), NVD: nvd.NewClient(opts.NVDAPIKey), KEV: kev.NewCatalog(), EPSS: epss.NewClient(),
		Extractors: all.Extractors(all.Options{GoProxy: opts.GoProxy}),
	}
	if opts.OSVURL != "" {
		r.OSV.APIURL = opts.OSVURL
	}
	if opts.NVDURL != "" {
		r.NVD.URL = opts.NVDURL
	}
	if opts.KEVURL != "" {
		r.KEV.URL = opts.KEVURL
	}
	if opts.EPSSURL != "" {
		r.EPSS.URL = opts.EPSSURL
	}
	return r
}

// Prepare loads required enrichment data before a one-shot scan. A server can
// instead refresh the same catalog through its existing feed lifecycle.
func (r *ScanRuntime) Prepare(ctx context.Context) error {
	if _, _, err := r.KEV.Refresh(ctx); err != nil {
		return fmt.Errorf("prepare KEV catalog: %w", err)
	}
	return nil
}

func (r *ScanRuntime) Matcher(cache vulndb.AdvisoryCache, log *slog.Logger) *vulndb.Matcher {
	return &vulndb.Matcher{OSV: r.OSV, NVD: r.NVD, KEV: r.KEV, EPSS: r.EPSS, Cache: cache, Log: log}
}

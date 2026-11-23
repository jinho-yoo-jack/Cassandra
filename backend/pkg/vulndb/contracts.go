package vulndb

import (
	"context"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

// AdvisoryCache stores raw normalised advisories by ID and primary CVE alias.
// Implementations must support concurrent calls and isolate stored records from
// mutation of both Put inputs and Get results. Get treats a read failure as a miss.
// Put replaces the ID record, but preserves an existing CVE alias record.
// Callers provide non-nil advisories with non-empty IDs.
type AdvisoryCache interface {
	Get(string) (*v1alpha1.Vulnerability, bool)
	Put(*v1alpha1.Vulnerability) error
}

// OSVProvider supplies package matches and advisory details, not feed sync.
type OSVProvider interface {
	QueryBatch(context.Context, []osv.Query) ([][]osv.VulnRef, error)
	Get(context.Context, string) (*osv.Vulnerability, error)
}

// NVDProvider supplies process matches and CVE lookup, not feed sync.
type NVDProvider interface {
	CVEsByCPE(context.Context, string) ([]nvd.CVE, error)
	CVE(context.Context, string) (*nvd.CVE, error)
}

// KEVProvider reads the catalog without requiring refresh or storage APIs.
type KEVProvider interface {
	Lookup(string) (*v1alpha1.KEV, bool)
}

// EPSSProvider supplies current exploit prediction scores.
type EPSSProvider interface {
	Scores(context.Context, []string) (map[string]*v1alpha1.EPSS, error)
}

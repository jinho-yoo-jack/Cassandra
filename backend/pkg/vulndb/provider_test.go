package vulndb

import (
	"context"
	"log/slog"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

// Function adapters keep tests on the same small contracts used by the matcher.
func testMatcher() *Matcher {
	return &Matcher{
		Log:   slog.Default(),
		Cache: NewMemoryCache(),
		OSV: osvStub{
			batch: func(_ context.Context, qs []osv.Query) ([][]osv.VulnRef, error) {
				return make([][]osv.VulnRef, len(qs)), nil
			},
			get: func(_ context.Context, id string) (*osv.Vulnerability, error) { return &osv.Vulnerability{ID: id}, nil },
		},
		NVD: nvdStub{
			byCPE: func(context.Context, string) ([]nvd.CVE, error) { return nil, nil },
			get:   func(_ context.Context, id string) (*nvd.CVE, error) { return &nvd.CVE{ID: id}, nil },
		},
		KEV:  kevFunc(func(string) (*v1alpha1.KEV, bool) { return nil, false }),
		EPSS: epssFunc(func(context.Context, []string) (map[string]*v1alpha1.EPSS, error) { return nil, nil }),
	}
}

type osvStub struct {
	batch func(context.Context, []osv.Query) ([][]osv.VulnRef, error)
	get   func(context.Context, string) (*osv.Vulnerability, error)
}

func (s osvStub) QueryBatch(ctx context.Context, qs []osv.Query) ([][]osv.VulnRef, error) {
	return s.batch(ctx, qs)
}
func (s osvStub) Get(ctx context.Context, id string) (*osv.Vulnerability, error) {
	return s.get(ctx, id)
}

type nvdStub struct {
	byCPE func(context.Context, string) ([]nvd.CVE, error)
	get   func(context.Context, string) (*nvd.CVE, error)
}

func (s nvdStub) CVEsByCPE(ctx context.Context, cpe string) ([]nvd.CVE, error) {
	return s.byCPE(ctx, cpe)
}
func (s nvdStub) CVE(ctx context.Context, id string) (*nvd.CVE, error) {
	return s.get(ctx, id)
}

type epssFunc func(context.Context, []string) (map[string]*v1alpha1.EPSS, error)

func (f epssFunc) Scores(ctx context.Context, ids []string) (map[string]*v1alpha1.EPSS, error) {
	return f(ctx, ids)
}

type kevFunc func(string) (*v1alpha1.KEV, bool)

func (f kevFunc) Lookup(id string) (*v1alpha1.KEV, bool) { return f(id) }

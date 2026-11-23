package vulndb

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/util/httpjson"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

func TestLookupRejectsMissingRecords(t *testing.T) {
	for _, stage := range []string{"OSV nil", "OSV empty", "NVD nil", "NVD empty"} {
		t.Run(stage, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("malformed lookup panicked: %v", p)
				}
			}()
			m := testMatcher()
			m.OSV = osvStub{get: func(context.Context, string) (*osv.Vulnerability, error) {
				if strings.HasPrefix(stage, "NVD") {
					return nil, &httpjson.StatusError{Code: http.StatusNotFound}
				}
				if stage == "OSV nil" {
					return nil, nil
				}
				return &osv.Vulnerability{}, nil
			}}
			m.NVD = nvdStub{get: func(context.Context, string) (*nvd.CVE, error) {
				if stage == "NVD nil" {
					return nil, nil
				}
				return &nvd.CVE{}, nil
			}}
			v, err := m.Lookup(context.Background(), "CVE-2024-1234")
			if v != nil || err == nil || !strings.Contains(err.Error(), "CVE-2024-1234") {
				t.Fatalf("record=%+v error=%v; want contextual validation error", v, err)
			}
		})
	}
}

func TestAdvisoryCancellationAfterProviderReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := testMatcher()
	m.OSV = osvStub{get: func(context.Context, string) (*osv.Vulnerability, error) {
		cancel()
		return &osv.Vulnerability{ID: "GHSA-test"}, nil
	}}
	v, err := m.Advisory(ctx, "GHSA-test", osv.VulnRef{})
	if v != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("advisory=%+v error=%v; want cancellation", v, err)
	}
	if _, ok := m.Cache.Get("GHSA-test"); ok {
		t.Fatal("canceled advisory was cached")
	}
}

type failingCache struct{ err error }

func (f failingCache) Get(string) (*v1alpha1.Vulnerability, bool) { return nil, false }
func (f failingCache) Put(*v1alpha1.Vulnerability) error          { return f.err }

func TestLookupCacheWriteFailureKeepsAdvisory(t *testing.T) {
	m := testMatcher()
	m.Cache = failingCache{err: errors.New("cache unavailable")}
	v, err := m.Lookup(context.Background(), "GHSA-test")
	if err != nil || v == nil || v.ID != "GHSA-test" {
		t.Fatalf("optional cache failure lost advisory: %+v, %v", v, err)
	}
}

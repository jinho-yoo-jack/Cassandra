package vulndb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"testing"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/util/httpjson"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/kev"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

func TestLookupEnrichmentIsolatedFromProviders(t *testing.T) {
	m := testMatcher()
	const id = "CVE-2024-1234"
	if err := m.Cache.Put(&v1alpha1.Vulnerability{ID: id, CVE: id}); err != nil {
		t.Fatal(err)
	}
	k, e := &v1alpha1.KEV{RequiredAction: "update"}, &v1alpha1.EPSS{Score: 0.8}
	m.KEV = kevFunc(func(string) (*v1alpha1.KEV, bool) { return k, true })
	m.EPSS = epssFunc(func(context.Context, []string) (map[string]*v1alpha1.EPSS, error) {
		return map[string]*v1alpha1.EPSS{id: e}, nil
	})
	v, err := m.Lookup(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	v.KEV.RequiredAction = "changed"
	v.EPSS.Score = 0
	again, err := m.Lookup(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if again.KEV.RequiredAction != "update" || again.EPSS.Score != 0.8 {
		t.Fatalf("caller mutation leaked into providers: %+v %+v", again.KEV, again.EPSS)
	}
	if raw, _ := m.Cache.Get(id); raw.KEV != nil || raw.EPSS != nil {
		t.Fatalf("enrichment leaked into raw cache: %+v", raw)
	}
}

func TestLookupFallback(t *testing.T) {
	notFound := &httpjson.StatusError{Code: http.StatusNotFound}
	unavailable := errors.New("provider unavailable")
	for _, tc := range []struct {
		name, id, source string
		cached           bool
		osvErr, nvdErr   error
		wantCalls        []string
		wantErr          error
	}{
		{name: "cache first", id: "CVE-2024-1234", cached: true, source: "cache"},
		{name: "OSV", id: "GHSA-example", source: "osv", wantCalls: []string{"osv"}},
		{name: "CVE falls back after OSV 404", id: "CVE-2024-1234", source: "nvd", osvErr: notFound, wantCalls: []string{"osv", "nvd"}},
		{name: "wrapped OSV 404", id: "CVE-2024-1234", source: "nvd", osvErr: fmt.Errorf("OSV: %w", notFound), wantCalls: []string{"osv", "nvd"}},
		{name: "non-CVE does not fall back", id: "GHSA-example", osvErr: notFound, wantCalls: []string{"osv"}, wantErr: notFound},
		{name: "OSV outage does not fall back", id: "CVE-2024-1234", osvErr: unavailable, wantCalls: []string{"osv"}, wantErr: unavailable},
		{name: "NVD not found", id: "CVE-2024-1234", osvErr: notFound, nvdErr: notFound, wantCalls: []string{"osv", "nvd"}, wantErr: notFound},
		{name: "NVD outage", id: "CVE-2024-1234", osvErr: notFound, nvdErr: unavailable, wantCalls: []string{"osv", "nvd"}, wantErr: unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			cache := NewMemoryCache()
			if tc.cached {
				if err := cache.Put(&v1alpha1.Vulnerability{ID: "GHSA-cached", CVE: tc.id, Source: "cache"}); err != nil {
					t.Fatal(err)
				}
			}
			m := &Matcher{
				Cache: cache, Log: slog.Default(), KEV: kev.NewCatalog(),
				OSV: osvStub{get: func(ctx context.Context, id string) (*osv.Vulnerability, error) {
					calls = append(calls, "osv")
					if id != tc.id {
						t.Errorf("OSV id = %s", id)
					}
					return &osv.Vulnerability{ID: id}, tc.osvErr
				}},
				NVD: nvdStub{get: func(ctx context.Context, id string) (*nvd.CVE, error) {
					calls = append(calls, "nvd")
					if id != tc.id {
						t.Errorf("NVD id = %s", id)
					}
					return &nvd.CVE{ID: id}, tc.nvdErr
				}},
				EPSS: epssFunc(func(context.Context, []string) (map[string]*v1alpha1.EPSS, error) { return nil, nil }),
			}
			v, err := m.Lookup(context.Background(), tc.id)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if !reflect.DeepEqual(calls, tc.wantCalls) {
				t.Errorf("calls = %v, want %v", calls, tc.wantCalls)
			}
			if tc.wantErr != nil {
				if v != nil {
					t.Errorf("error returned advisory: %+v", v)
				}
				return
			}
			if v == nil || v.Source != tc.source {
				t.Fatalf("advisory = %+v", v)
			}
			if raw, ok := cache.Get(tc.id); !ok || raw.ID != v.ID {
				t.Fatalf("record not cached: %+v", raw)
			}
		})
	}
}

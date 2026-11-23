package vulndb

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/util/httpjson"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

func TestMatchCancellation(t *testing.T) {
	for _, stage := range []string{"before empty scan", "OSV batch", "OSV detail", "NVD", "EPSS"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(stage+"/"+cause.Error(), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				interrupt := cancel
				if cause == context.DeadlineExceeded {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
					defer stop()
					interrupt = func() { <-ctx.Done() }
				}
				m := testMatcher()
				inv := &inventory.Inventory{}
				library := inventory.NewLibrary(inventory.NPM, "example", "1.0.0", "package-lock.json", true, false)
				switch stage {
				case "before empty scan":
					interrupt()
				case "OSV batch":
					inv.Components = []*inventory.Component{library}
					m.OSV = osvStub{batch: func(context.Context, []osv.Query) ([][]osv.VulnRef, error) { interrupt(); return nil, cause }}
				case "OSV detail":
					inv.Components = []*inventory.Component{library}
					m.OSV = osvStub{
						batch: func(context.Context, []osv.Query) ([][]osv.VulnRef, error) {
							return [][]osv.VulnRef{{{ID: "GHSA-test"}}}, nil
						},
						get: func(context.Context, string) (*osv.Vulnerability, error) { interrupt(); return nil, cause },
					}
				case "NVD":
					inv.Components = []*inventory.Component{{ID: "nginx", Ecosystem: inventory.Process, Version: "1.0.0", CPEs: []string{"f5:nginx"}}}
					m.NVD = nvdStub{byCPE: func(context.Context, string) ([]nvd.CVE, error) { interrupt(); return nil, cause }}
				case "EPSS":
					m.EPSS = epssFunc(func(context.Context, []string) (map[string]*v1alpha1.EPSS, error) { interrupt(); return nil, cause })
				}
				res, err := m.Match(ctx, inv)
				if res != nil || !errors.Is(err, cause) {
					t.Fatalf("result=%+v error=%v; want no result and %v", res, err, cause)
				}
			})
		}
	}
}

func TestLookupCancellation(t *testing.T) {
	for _, stage := range []string{"before cached", "OSV", "NVD", "EPSS"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := testMatcher()
			const id = "CVE-2024-1234"
			switch stage {
			case "before cached":
				if err := m.Cache.Put(&v1alpha1.Vulnerability{ID: id}); err != nil {
					t.Fatal(err)
				}
				m.EPSS = epssFunc(func(context.Context, []string) (map[string]*v1alpha1.EPSS, error) {
					t.Error("enrichment called after cancellation")
					return nil, nil
				})
				cancel()
			case "OSV":
				m.OSV = osvStub{get: func(context.Context, string) (*osv.Vulnerability, error) {
					cancel()
					return nil, &httpjson.StatusError{Code: http.StatusNotFound}
				}}
				m.NVD = nvdStub{get: func(context.Context, string) (*nvd.CVE, error) {
					t.Error("NVD fallback called after cancellation")
					return &nvd.CVE{ID: id}, nil
				}}
			case "NVD":
				m.OSV = osvStub{get: func(context.Context, string) (*osv.Vulnerability, error) {
					return nil, &httpjson.StatusError{Code: http.StatusNotFound}
				}}
				m.NVD = nvdStub{get: func(context.Context, string) (*nvd.CVE, error) { cancel(); return nil, context.Canceled }}
			case "EPSS":
				m.EPSS = epssFunc(func(context.Context, []string) (map[string]*v1alpha1.EPSS, error) {
					cancel()
					return nil, context.Canceled
				})
			}
			v, err := m.Lookup(ctx, id)
			if v != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("advisory=%+v error=%v; want cancellation", v, err)
			}
		})
	}
}

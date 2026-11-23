package vulndb

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage/boltstore"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/epss"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/kev"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

func TestMatchRejectsMalformedBatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		refs [][]osv.VulnRef
	}{
		{"missing result", nil},
		{"extra result", [][]osv.VulnRef{{}, {}}},
		{"missing advisory id", [][]osv.VulnRef{{{ID: ""}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testMatcher()
			m.OSV = osvStub{
				batch: func(context.Context, []osv.Query) ([][]osv.VulnRef, error) { return tc.refs, nil },
				get:   func(_ context.Context, id string) (*osv.Vulnerability, error) { return &osv.Vulnerability{ID: id}, nil },
			}
			inv := &inventory.Inventory{Components: []*inventory.Component{
				inventory.NewLibrary(inventory.NPM, "example", "1.0.0", "package-lock.json", true, false),
			}}
			res, err := m.Match(context.Background(), inv)
			if err == nil || res != nil || !strings.Contains(err.Error(), "OSV") {
				t.Fatalf("malformed batch returned result=%+v error=%v", res, err)
			}
		})
	}
}

func TestAdvisoryRejectsMalformedRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    *osv.Vulnerability
	}{
		{"nil", nil},
		{"missing id", &osv.Vulnerability{}},
		{"mismatched id", &osv.Vulnerability{ID: "GHSA-other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("malformed advisory panicked: %v", p)
				}
			}()
			m := testMatcher()
			m.OSV = osvStub{get: func(context.Context, string) (*osv.Vulnerability, error) { return tc.v, nil }}
			v, err := m.Advisory(context.Background(), "GHSA-test", osv.VulnRef{Modified: time.Now()})
			if err == nil || v != nil || !strings.Contains(err.Error(), "GHSA-test") {
				t.Fatalf("malformed advisory returned record=%+v error=%v", v, err)
			}
		})
	}
}

func TestMatchFailsWhenOSVAdvisoryCannotBeFetched(t *testing.T) {
	const id = "GHSA-unavailable"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"` + id + `"}]}]}`))
			return
		}
		http.Error(w, "advisory unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()
	o := osv.NewClient()
	o.APIURL = srv.URL
	db, err := boltstore.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	blobs, err := boltstore.NewBlobs(db, "vulns")
	if err != nil {
		t.Fatal(err)
	}
	m := &Matcher{OSV: o, Cache: NewCache(blobs), KEV: kev.NewCatalog(), EPSS: epss.NewClient(), Log: slog.Default()}
	inv := &inventory.Inventory{Components: []*inventory.Component{
		inventory.NewLibrary(inventory.NPM, "example", "1.0.0", "package-lock.json", true, false),
	}}
	res, err := m.Match(context.Background(), inv)
	if err == nil {
		t.Fatalf("required OSV advisory failure returned a successful (incomplete) scan: %+v", res)
	}
	if res != nil || !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "502") {
		t.Fatalf("got result=%+v error=%v; want no result and advisory/provider error context", res, err)
	}
}

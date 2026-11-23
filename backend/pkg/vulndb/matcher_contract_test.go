package vulndb

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

func TestMatchPreservesOptionalProviderWarnings(t *testing.T) {
	m := testMatcher()
	m.NVD = nvdStub{byCPE: func(context.Context, string) ([]nvd.CVE, error) { return nil, errors.New("NVD unavailable") }}
	m.EPSS = epssFunc(func(context.Context, []string) (map[string]*v1alpha1.EPSS, error) {
		return nil, errors.New("EPSS unavailable")
	})
	inv := &inventory.Inventory{Components: []*inventory.Component{{ID: "nginx", Ecosystem: inventory.Process, Version: "1.0.0", CPEs: []string{"f5:nginx"}}}}
	res, err := m.Match(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 2 || !strings.Contains(res.Warnings[0], "NVD f5:nginx 1.0.0:") || res.Warnings[1] != "EPSS: EPSS unavailable" {
		t.Fatalf("warnings changed: %+v", res.Warnings)
	}
}

func TestLookupPreservesEPSSWarning(t *testing.T) {
	m := testMatcher()
	var logs bytes.Buffer
	m.Log = slog.New(slog.NewTextHandler(&logs, nil))
	m.EPSS = epssFunc(func(context.Context, []string) (map[string]*v1alpha1.EPSS, error) {
		return nil, errors.New("EPSS unavailable")
	})
	v, err := m.Lookup(context.Background(), "CVE-2024-1234")
	if err != nil || v == nil || !strings.Contains(logs.String(), "EPSS lookup failed") {
		t.Fatalf("advisory=%+v error=%v logs=%s", v, err, logs.String())
	}
}

func TestAdvisoryCacheFreshness(t *testing.T) {
	now := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, id   string
		cachedTime time.Time
		wantCalls  int
	}{
		{"fresh", "GHSA-test", now, 0},
		{"stale", "GHSA-test", now.Add(-time.Hour), 1},
		{"alias is not canonical", "CVE-2024-1234", now, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testMatcher()
			if err := m.Cache.Put(&v1alpha1.Vulnerability{ID: "GHSA-test", CVE: "CVE-2024-1234", Modified: tc.cachedTime}); err != nil {
				t.Fatal(err)
			}
			calls := 0
			m.OSV = osvStub{get: func(_ context.Context, id string) (*osv.Vulnerability, error) {
				calls++
				return &osv.Vulnerability{ID: id, Modified: now}, nil
			}}
			v, err := m.Advisory(context.Background(), tc.id, osv.VulnRef{Modified: now})
			if err != nil || v.ID != tc.id || !v.Modified.Equal(now) || calls != tc.wantCalls {
				t.Fatalf("record=%+v error=%v calls=%d", v, err, calls)
			}
		})
	}
}

func TestMatchDistinctAdvisoryUsesNewestRefAndExcludesWithdrawn(t *testing.T) {
	now := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	for _, withdrawn := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "withdrawn"}[withdrawn], func(t *testing.T) {
			m := testMatcher()
			old := now.Add(-time.Hour)
			if err := m.Cache.Put(&v1alpha1.Vulnerability{ID: "GHSA-test", Modified: old}); err != nil {
				t.Fatal(err)
			}
			calls := 0
			m.OSV = osvStub{
				batch: func(context.Context, []osv.Query) ([][]osv.VulnRef, error) {
					return [][]osv.VulnRef{{{ID: "GHSA-test", Modified: old}}, {{ID: "GHSA-test", Modified: now}}}, nil
				},
				get: func(context.Context, string) (*osv.Vulnerability, error) {
					calls++
					v := &osv.Vulnerability{ID: "GHSA-test", Modified: now}
					if withdrawn {
						v.Withdrawn = &now
					}
					return v, nil
				},
			}
			inv := &inventory.Inventory{Components: []*inventory.Component{
				inventory.NewLibrary(inventory.NPM, "first", "1.0.0", "package-lock.json", true, false),
				inventory.NewLibrary(inventory.NPM, "second", "1.0.0", "package-lock.json", true, false),
			}}
			res, err := m.Match(context.Background(), inv)
			if err != nil {
				t.Fatal(err)
			}
			wantFindings := 2
			if withdrawn {
				wantFindings = 0
			}
			if calls != 1 || len(res.Findings) != wantFindings {
				t.Fatalf("distinct/withdrawn handling: calls=%d result=%+v", calls, res)
			}
		})
	}
}

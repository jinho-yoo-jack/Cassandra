package vulndb

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage/boltstore"
)

func newBoltCache(t *testing.T) AdvisoryCache {
	t.Helper()
	db, err := boltstore.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blobs, err := boltstore.NewBlobs(db, "vulns")
	if err != nil {
		t.Fatal(err)
	}
	return NewCache(blobs)
}

func cacheFixture() *v1alpha1.Vulnerability {
	withdrawn := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	return &v1alpha1.Vulnerability{
		TypeMeta: v1alpha1.NewTypeMeta(v1alpha1.KindVulnerability),
		ID:       "GHSA-cache", CVE: "CVE-2024-1234", Aliases: []string{"CVE-2024-1234"},
		Summary: "original", Severity: v1alpha1.SeverityHigh, Source: "osv",
		CVSS: &v1alpha1.CVSS{Score: 7.5}, EPSS: &v1alpha1.EPSS{Score: 0.8},
		KEV: &v1alpha1.KEV{RequiredAction: "update"}, CWEs: []string{"CWE-79"},
		Withdrawn: &withdrawn, References: []v1alpha1.Reference{{URL: "https://example.test/advisory"}},
		Affected: []v1alpha1.AffectedPackage{{Ecosystem: "npm", Name: "example", Ranges: []v1alpha1.AffectedRange{{Introduced: "0", Fixed: "2.0.0"}}}},
	}
}

func mutateAdvisory(v *v1alpha1.Vulnerability) {
	v.Summary = "changed"
	v.Aliases[0] = "changed"
	v.CVSS.Score = 0
	v.EPSS.Score = 0
	v.KEV.RequiredAction = "changed"
	v.CWEs[0] = "changed"
	*v.Withdrawn = time.Time{}
	v.References[0].URL = "changed"
	v.Affected[0].Name = "changed"
	v.Affected[0].Ranges[0].Fixed = "changed"
}

func TestAdvisoryCacheContract(t *testing.T) {
	factories := map[string]func(*testing.T) AdvisoryCache{
		"bolt":   newBoltCache,
		"memory": func(*testing.T) AdvisoryCache { return NewMemoryCache() },
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			cache := factory(t)
			if v, ok := cache.Get("missing"); ok || v != nil {
				t.Fatalf("miss = %+v, %v", v, ok)
			}
			v, want := cacheFixture(), cacheFixture()
			if err := cache.Put(v); err != nil {
				t.Fatal(err)
			}
			mutateAdvisory(v)
			for _, id := range []string{want.ID, want.CVE} {
				got, ok := cache.Get(id)
				if !ok || !reflect.DeepEqual(got, want) {
					t.Fatalf("Put input mutation affected %s: %+v", id, got)
				}
				mutateAdvisory(got)
				again, ok := cache.Get(id)
				if !ok || !reflect.DeepEqual(again, want) {
					t.Fatalf("Get result mutation affected %s: %+v", id, again)
				}
			}
			// Match the existing persistent cache's first-alias-wins policy.
			other := cacheFixture()
			other.ID = "GO-cache"
			if err := cache.Put(other); err != nil {
				t.Fatal(err)
			}
			if alias, _ := cache.Get(want.CVE); !reflect.DeepEqual(alias, want) {
				t.Fatalf("alias overwritten by another advisory: %+v", alias)
			}
			updated := cacheFixture()
			updated.Summary = "updated"
			if err := cache.Put(updated); err != nil {
				t.Fatal(err)
			}
			if got, _ := cache.Get(want.ID); !reflect.DeepEqual(got, updated) {
				t.Fatalf("ID not replaced: %+v", got)
			}

			var wg sync.WaitGroup
			for i := range 12 {
				wg.Go(func() {
					entry := cacheFixture()
					entry.ID = fmt.Sprintf("GHSA-concurrent-%d", i)
					entry.CVE = fmt.Sprintf("CVE-2024-%04d", 5000+i)
					if err := cache.Put(entry); err != nil {
						t.Error(err)
						return
					}
					for range 5 {
						got, ok := cache.Get(entry.CVE)
						if !ok || !reflect.DeepEqual(got, entry) {
							t.Errorf("concurrent round trip failed: %+v", got)
							return
						}
						mutateAdvisory(got)
					}
				})
			}
			wg.Wait()
		})
	}
}

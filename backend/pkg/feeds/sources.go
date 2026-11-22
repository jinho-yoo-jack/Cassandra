package feeds

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/kev"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/nvd"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb/osv"
)

// keysFromAffected returns the package keys an advisory affects.
func keysFromAffected(v *v1alpha1.Vulnerability) []PackageKey {
	var keys []PackageKey
	for _, a := range v.Affected {
		keys = append(keys, NewPackageKey(normalizeEcosystem(a.Ecosystem), a.Name))
	}
	return keys
}

// ---------------------------------------------------------------------------
// OSV
// ---------------------------------------------------------------------------

// OSVSource follows <ecosystem>/modified_id.csv of the OSV export bucket.
type OSVSource struct {
	Client     *osv.Client
	Cache      *vulndb.Cache
	Ecosystems []string
	Every      time.Duration
	// BatchSize bounds how many records one run fetches per ecosystem; the
	// rest is picked up by the next run.
	BatchSize int
}

func (s *OSVSource) Name() string            { return "osv" }
func (s *OSVSource) Mode() string            { return "pull" }
func (s *OSVSource) Interval() time.Duration { return s.Every }

// Sync implements Source. The first run only records a baseline: scans
// query OSV directly, so history before the server started is not needed.
func (s *OSVSource) Sync(ctx context.Context, status *v1alpha1.FeedStatus) (Changes, error) {
	var changes Changes
	now := time.Now().UTC()
	for _, eco := range s.Ecosystems {
		cursor, ok := status.Cursors[eco]
		if !ok {
			status.Cursors[eco] = now
			continue
		}
		entries, err := s.Client.ModifiedSince(ctx, eco, cursor)
		if err != nil {
			return changes, fmt.Errorf("%s: %w", eco, err)
		}
		slices.Reverse(entries) // oldest first, so the cursor only moves forward
		if len(entries) > s.BatchSize {
			entries = entries[:s.BatchSize]
		}
		for _, e := range entries {
			o, err := s.Client.Get(ctx, e.ID)
			if err != nil {
				return changes, fmt.Errorf("%s %s: %w", eco, e.ID, err)
			}
			v := vulndb.FromOSV(o)
			if err := s.Cache.Put(v); err != nil {
				return changes, err
			}
			changes.Packages = append(changes.Packages, keysFromAffected(v)...)
			status.Cursors[eco] = e.Modified
			status.Processed++
		}
	}
	return changes, nil
}

// ---------------------------------------------------------------------------
// NVD
// ---------------------------------------------------------------------------

// NVDSource follows NVD's lastModified window. Only CPE based matches use
// NVD, so changes are reported as CPE package keys.
type NVDSource struct {
	Client *nvd.Client
	Cache  *vulndb.Cache
	Every  time.Duration
}

func (s *NVDSource) Name() string            { return "nvd" }
func (s *NVDSource) Mode() string            { return "pull" }
func (s *NVDSource) Interval() time.Duration { return s.Every }

const nvdCursor = "lastModified"

// Sync implements Source.
func (s *NVDSource) Sync(ctx context.Context, status *v1alpha1.FeedStatus) (Changes, error) {
	var changes Changes
	now := time.Now().UTC()
	start, ok := status.Cursors[nvdCursor]
	if !ok {
		status.Cursors[nvdCursor] = now
		return changes, nil
	}
	end := start.Add(nvd.MaxRange)
	if end.After(now) {
		end = now
	}
	err := s.Client.ModifiedBetween(ctx, start, end, func(c nvd.CVE) error {
		v := vulndb.FromNVD(&c)
		if _, cached := s.Cache.Get(v.ID); cached {
			if err := s.Cache.Put(v); err != nil {
				return err
			}
		}
		for _, k := range keysFromAffected(v) {
			if k.Ecosystem == vulndb.EcosystemCPE {
				changes.Packages = append(changes.Packages, k)
			}
		}
		status.Processed++
		return nil
	})
	if err != nil {
		return changes, err
	}
	status.Cursors[nvdCursor] = end
	return changes, nil
}

// ---------------------------------------------------------------------------
// CISA KEV
// ---------------------------------------------------------------------------

// KEVSource refreshes the KEV catalog; newly listed CVEs are reported so
// scans containing them get re-enriched.
type KEVSource struct {
	Catalog *kev.Catalog
	Every   time.Duration
}

func (s *KEVSource) Name() string            { return "cisa-kev" }
func (s *KEVSource) Mode() string            { return "pull" }
func (s *KEVSource) Interval() time.Duration { return s.Every }

// Sync implements Source.
func (s *KEVSource) Sync(ctx context.Context, status *v1alpha1.FeedStatus) (Changes, error) {
	added, _, err := s.Catalog.Refresh(ctx)
	if err != nil {
		return Changes{}, err
	}
	status.Cursors["catalog"] = time.Now().UTC()
	status.Processed += int64(len(added))
	return Changes{CVEs: added}, nil
}

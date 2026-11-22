package feeds

import (
	"context"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage"
)

// Source is one upstream feed.
type Source interface {
	Name() string
	// Mode is "pull" for polled sources and "push" for webhooks.
	Mode() string
	Interval() time.Duration
	// Sync processes everything newer than the cursors in status, advancing
	// them only past records that were processed successfully, so failures
	// are retried on the next run (at-least-once).
	Sync(ctx context.Context, status *v1alpha1.FeedStatus) (Changes, error)
}

// Syncer runs every pull source on its interval and records the outcome of
// each run in the matching Feed object.
type Syncer struct {
	Feeds   storage.Interface[*v1alpha1.Feed]
	Sources []Source
	Sink    Sink
	Log     *slog.Logger
}

// Run blocks until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	for _, src := range s.Sources {
		if err := s.ensureFeed(ctx, src.Name(), src.Mode(), src.Interval()); err != nil {
			s.Log.Error("[feeds] Create feed object failed", "feed", src.Name(), "err", err)
		}
	}
	for _, src := range s.Sources {
		if src.Mode() != "pull" {
			continue
		}
		go wait.JitterUntilWithContext(ctx, func(ctx context.Context) { s.syncOnce(ctx, src) }, src.Interval(), 0.1, true)
	}
	<-ctx.Done()
}

func (s *Syncer) ensureFeed(ctx context.Context, name, mode string, interval time.Duration) error {
	_, err := s.Feeds.Create(ctx, &v1alpha1.Feed{
		TypeMeta:   v1alpha1.NewTypeMeta(v1alpha1.KindFeed),
		ObjectMeta: v1alpha1.ObjectMeta{Name: name},
		Status:     v1alpha1.FeedStatus{Source: name, Mode: mode, Interval: interval.String()},
	})
	if storage.IsExist(err) {
		return nil
	}
	return err
}

func (s *Syncer) syncOnce(ctx context.Context, src Source) {
	feed, err := s.Feeds.Get(ctx, src.Name())
	if err != nil {
		s.Log.Error("[feeds] Get feed failed", "feed", src.Name(), "err", err)
		return
	}
	status := feed.Status
	if status.Cursors == nil {
		status.Cursors = map[string]time.Time{}
	}
	before := status.Processed
	changes, err := src.Sync(ctx, &status)
	if ctx.Err() != nil {
		return
	}
	s.Record(ctx, src.Name(), status, changes, err)
	s.Log.Info("[feeds] Synced", "feed", src.Name(), "processed", status.Processed-before, "packages", len(changes.Packages), "cves", len(changes.CVEs), "err", err)
}

// Record stores the outcome of a sync and forwards changes to the sink. Push
// sources call it directly.
func (s *Syncer) Record(ctx context.Context, name string, status v1alpha1.FeedStatus, changes Changes, syncErr error) {
	now := time.Now().UTC()
	status.LastSyncTime = &now
	if syncErr != nil {
		status.LastError = syncErr.Error()
	} else {
		status.LastError, status.LastSuccessTime = "", &now
	}
	if !changes.Empty() && s.Sink != nil {
		status.Matched += int64(s.Sink.Notify(changes))
	}
	if _, err := s.Feeds.GuaranteedUpdate(ctx, name, func(cur *v1alpha1.Feed) (*v1alpha1.Feed, error) {
		cur.Status = status
		return cur, nil
	}); err != nil {
		s.Log.Error("[feeds] Update feed status failed", "feed", name, "err", err)
	}
}

// Status returns the current status of a feed, for push sources.
func (s *Syncer) Status(ctx context.Context, name string) (v1alpha1.FeedStatus, error) {
	f, err := s.Feeds.Get(ctx, name)
	if err != nil {
		return v1alpha1.FeedStatus{}, err
	}
	return f.Status, nil
}

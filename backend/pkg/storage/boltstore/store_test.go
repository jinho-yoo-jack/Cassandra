package boltstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/storage"
	"github.com/jinho-yoo-jack/vulngraph/pkg/watch"
)

func newTestStore(t *testing.T) *Store[*v1alpha1.Scan] {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db, "scans", func() *v1alpha1.Scan { return &v1alpha1.Scan{} })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newScan(name string) *v1alpha1.Scan {
	return &v1alpha1.Scan{ObjectMeta: v1alpha1.ObjectMeta{Name: name}, Spec: v1alpha1.ScanSpec{RepositoryURL: "https://github.com/a/b"}}
}

func TestCreateGetDelete(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	created, err := s.Create(ctx, newScan("a"))
	if err != nil {
		t.Fatal(err)
	}
	if created.UID == "" || created.ResourceVersion == "" || created.CreationTimestamp.IsZero() {
		t.Fatalf("store did not assign identity fields: %+v", created.ObjectMeta)
	}
	if _, err := s.Create(ctx, newScan("a")); !storage.IsExist(err) {
		t.Fatalf("second create: want exists error, got %v", err)
	}
	got, err := s.Get(ctx, "a")
	if err != nil || got.UID != created.UID {
		t.Fatalf("get: %v %+v", err, got)
	}
	if _, err := s.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "a"); !storage.IsNotFound(err) {
		t.Fatalf("get after delete: want not found, got %v", err)
	}
}

func TestGuaranteedUpdate(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	created, _ := s.Create(ctx, newScan("a"))

	tests := []struct {
		name       string
		mutate     func(*v1alpha1.Scan)
		wantErr    func(error) bool
		wantRVBump bool
		wantPhase  v1alpha1.ScanPhase
	}{
		{
			name:       "changes bump resourceVersion",
			mutate:     func(s *v1alpha1.Scan) { s.Status.Phase = v1alpha1.ScanRunning },
			wantRVBump: true,
			wantPhase:  v1alpha1.ScanRunning,
		},
		{
			name:      "no-op keeps resourceVersion",
			mutate:    func(s *v1alpha1.Scan) {},
			wantPhase: v1alpha1.ScanRunning,
		},
		{
			name:    "stale resourceVersion conflicts",
			mutate:  func(s *v1alpha1.Scan) { s.ResourceVersion = created.ResourceVersion },
			wantErr: storage.IsConflict,
		},
		{
			name:      "identity fields cannot be changed",
			mutate:    func(s *v1alpha1.Scan) { s.UID = "forged" },
			wantPhase: v1alpha1.ScanRunning,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, _ := s.Get(ctx, "a")
			after, err := s.GuaranteedUpdate(ctx, "a", func(cur *v1alpha1.Scan) (*v1alpha1.Scan, error) {
				tt.mutate(cur)
				return cur, nil
			})
			if tt.wantErr != nil {
				if !tt.wantErr(err) {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if bumped := after.ResourceVersion != before.ResourceVersion; bumped != tt.wantRVBump {
				t.Errorf("resourceVersion bumped=%v, want %v", bumped, tt.wantRVBump)
			}
			if after.Status.Phase != tt.wantPhase {
				t.Errorf("phase=%s, want %s", after.Status.Phase, tt.wantPhase)
			}
			if after.UID != created.UID {
				t.Errorf("UID changed to %s", after.UID)
			}
		})
	}
}

func TestWatchSendsInitialEventsThenChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newTestStore(t)
	s.Create(ctx, newScan("existing"))

	w, err := s.Watch(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	s.Create(ctx, newScan("new"))

	want := []struct {
		typ  watch.EventType
		name string
	}{{watch.Added, "existing"}, {watch.Added, "new"}}
	for _, exp := range want {
		select {
		case ev := <-w.ResultChan():
			if ev.Type != exp.typ || ev.Object.(*v1alpha1.Scan).Name != exp.name {
				t.Fatalf("got %s %s, want %s %s", ev.Type, ev.Object.(*v1alpha1.Scan).Name, exp.typ, exp.name)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
}

package reportstore

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/codegraph"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage/boltstore"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/vulndb"
)

func TestReportStorageCompatibility(t *testing.T) {
	db, err := boltstore.Open(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	blobs, err := boltstore.NewBlobs(db, "reports")
	if err != nil {
		t.Fatal(err)
	}
	store := New(blobs)
	want := &report.Report{Repository: v1alpha1.RepositoryInfo{Name: "existing"}, Inventory: &inventory.Inventory{}, Code: &codegraph.Graph{}, Match: &vulndb.Result{}, GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	// A raw blob written with the existing schema must remain readable.
	if err := blobs.Put("old", want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("old")
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if err := store.Put("new", want); err != nil {
		t.Fatal(err)
	}
	keys, err := store.Names()
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	if err := store.Delete("old"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("old"); !storage.IsNotFound(err) {
		t.Fatalf("missing error=%v", err)
	}
	if err := store.Delete("old"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

// Package boltstore implements storage.Interface on top of bbolt, the
// embedded B+tree that also backs etcd.
package boltstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/watch"
)

var (
	metaBucket  = []byte("_meta")
	revisionKey = []byte("revision")
)

// Open opens (or creates) the database file.
func Open(path string) (*bolt.DB, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(metaBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// Store is a typed storage.Interface backed by one bbolt bucket.
type Store[T storage.Object] struct {
	// writeMu orders "commit, then publish" so watchers observe events in
	// commit order. bbolt already serialises writers, so it costs nothing.
	writeMu     sync.Mutex
	db          *bolt.DB
	bucket      []byte
	newFunc     func() T
	broadcaster *watch.Broadcaster
}

var _ storage.Interface[storage.Object] = (*Store[storage.Object])(nil)

// New returns a store for one resource. newFunc must return a new, empty
// object (like rest.Storage.New in the apiserver).
func New[T storage.Object](db *bolt.DB, resource string, newFunc func() T) (*Store[T], error) {
	bucket := []byte(resource)
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucket)
		return err
	}); err != nil {
		return nil, fmt.Errorf("create bucket %s: %w", resource, err)
	}
	return &Store[T]{db: db, bucket: bucket, newFunc: newFunc, broadcaster: watch.NewBroadcaster()}, nil
}

// Shutdown terminates all watchers.
func (s *Store[T]) Shutdown() { s.broadcaster.Shutdown() }

func (s *Store[T]) key(name string) string { return string(s.bucket) + "/" + name }

func (s *Store[T]) decode(data []byte) (T, error) {
	obj := s.newFunc()
	if err := json.Unmarshal(data, obj); err != nil {
		var zero T
		return zero, fmt.Errorf("decode %s: %w", s.bucket, err)
	}
	return obj, nil
}

// nextRevision bumps the global revision, shared by all buckets like an etcd
// revision, so resourceVersions are comparable across resources.
func nextRevision(tx *bolt.Tx) (string, error) {
	b := tx.Bucket(metaBucket)
	rev, err := b.NextSequence()
	if err != nil {
		return "", err
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, rev)
	if err := b.Put(revisionKey, buf); err != nil {
		return "", err
	}
	return strconv.FormatUint(rev, 10), nil
}

func currentRevision(tx *bolt.Tx) string {
	return strconv.FormatUint(tx.Bucket(metaBucket).Sequence(), 10)
}

func newUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Create implements storage.Interface.
func (s *Store[T]) Create(ctx context.Context, obj T) (T, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var zero T
	meta := obj.GetObjectMeta()
	if meta.Name == "" {
		return zero, fmt.Errorf("name is required")
	}
	var data []byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(s.bucket)
		if b.Get([]byte(meta.Name)) != nil {
			return storage.NewExistsError(s.key(meta.Name))
		}
		rev, err := nextRevision(tx)
		if err != nil {
			return err
		}
		meta.UID = newUID()
		meta.ResourceVersion = rev
		meta.Generation = 1
		meta.CreationTimestamp = time.Now().UTC().Truncate(time.Second)
		if data, err = json.Marshal(obj); err != nil {
			return err
		}
		return b.Put([]byte(meta.Name), data)
	})
	if err != nil {
		return zero, err
	}
	s.publish(watch.Added, data)
	return s.decode(data)
}

// Get implements storage.Interface.
func (s *Store[T]) Get(ctx context.Context, name string) (T, error) {
	var data []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(s.bucket).Get([]byte(name))
		if v == nil {
			return storage.NewNotFoundError(s.key(name))
		}
		data = bytes.Clone(v)
		return nil
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return s.decode(data)
}

// List implements storage.Interface.
func (s *Store[T]) List(ctx context.Context) ([]T, string, error) {
	var (
		items []T
		rev   string
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		rev = currentRevision(tx)
		return tx.Bucket(s.bucket).ForEach(func(_, v []byte) error {
			obj, err := s.decode(v)
			if err != nil {
				return err
			}
			items = append(items, obj)
			return nil
		})
	})
	return items, rev, err
}

// GuaranteedUpdate implements storage.Interface. bbolt serialises writers, so
// the read-modify-write below can never observe a concurrent update.
func (s *Store[T]) GuaranteedUpdate(ctx context.Context, name string, tryUpdate storage.UpdateFunc[T]) (T, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var (
		zero    T
		data    []byte
		changed bool
	)
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(s.bucket)
		cur := b.Get([]byte(name))
		if cur == nil {
			return storage.NewNotFoundError(s.key(name))
		}
		curObj, err := s.decode(cur)
		if err != nil {
			return err
		}
		curMeta := *curObj.GetObjectMeta()

		updated, err := tryUpdate(curObj)
		if err != nil {
			return err
		}
		meta := updated.GetObjectMeta()
		if meta.ResourceVersion != "" && meta.ResourceVersion != curMeta.ResourceVersion {
			return storage.NewConflictError(s.key(name),
				fmt.Sprintf("resourceVersion %s does not match current %s", meta.ResourceVersion, curMeta.ResourceVersion))
		}
		// Identity fields are owned by the store.
		meta.Name, meta.UID, meta.CreationTimestamp = curMeta.Name, curMeta.UID, curMeta.CreationTimestamp
		meta.ResourceVersion, meta.Generation = curMeta.ResourceVersion, curMeta.Generation

		candidate, err := json.Marshal(updated)
		if err != nil {
			return err
		}
		if bytes.Equal(candidate, cur) {
			data = bytes.Clone(cur)
			return nil // no-op update: no new revision, no event
		}
		if meta.ResourceVersion, err = nextRevision(tx); err != nil {
			return err
		}
		if data, err = json.Marshal(updated); err != nil {
			return err
		}
		changed = true
		return b.Put([]byte(name), data)
	})
	if err != nil {
		return zero, err
	}
	if changed {
		s.publish(watch.Modified, data)
	}
	return s.decode(data)
}

// Delete implements storage.Interface.
func (s *Store[T]) Delete(ctx context.Context, name string) (T, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var (
		zero T
		data []byte
	)
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(s.bucket)
		v := b.Get([]byte(name))
		if v == nil {
			return storage.NewNotFoundError(s.key(name))
		}
		data = bytes.Clone(v)
		if _, err := nextRevision(tx); err != nil {
			return err
		}
		return b.Delete([]byte(name))
	})
	if err != nil {
		return zero, err
	}
	s.publish(watch.Deleted, data)
	return s.decode(data)
}

// Watch implements storage.Interface.
func (s *Store[T]) Watch(ctx context.Context, sendInitialEvents bool) (watch.Interface, error) {
	w, err := s.broadcaster.WatchWithPrefix(func() ([]watch.Event, error) {
		if !sendInitialEvents {
			return nil, nil
		}
		items, _, err := s.List(ctx)
		if err != nil {
			return nil, err
		}
		events := make([]watch.Event, 0, len(items))
		for _, it := range items {
			events = append(events, watch.Event{Type: watch.Added, Object: it})
		}
		return events, nil
	})
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		w.Stop()
	}()
	return w, nil
}

// publish decodes a fresh copy per event so watchers never share memory with
// the caller.
func (s *Store[T]) publish(t watch.EventType, data []byte) {
	obj, err := s.decode(data)
	if err != nil {
		return
	}
	s.broadcaster.Action(t, obj)
}

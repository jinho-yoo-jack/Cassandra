package boltstore

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	bolt "go.etcd.io/bbolt"

	"github.com/jinho-yoo-jack/vulngraph/pkg/storage"
)

// Blobs stores large, gzip-compressed JSON documents (scan reports, cached
// advisories) that are not API objects and therefore are not watched.
type Blobs struct {
	db     *bolt.DB
	bucket []byte
}

// NewBlobs returns a blob bucket.
func NewBlobs(db *bolt.DB, bucket string) (*Blobs, error) {
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		return err
	}); err != nil {
		return nil, fmt.Errorf("create bucket %s: %w", bucket, err)
	}
	return &Blobs{db: db, bucket: []byte(bucket)}, nil
}

// Put stores v under key.
func (b *Blobs) Put(key string, v any) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(b.bucket).Put([]byte(key), buf.Bytes())
	})
}

// Get decodes the value stored under key into v.
func (b *Blobs) Get(key string, v any) error {
	var data []byte
	if err := b.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(b.bucket).Get([]byte(key))
		if raw == nil {
			return storage.NewNotFoundError(string(b.bucket) + "/" + key)
		}
		data = bytes.Clone(raw)
		return nil
	}); err != nil {
		return err
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer zr.Close()
	return json.NewDecoder(io.LimitReader(zr, 1<<30)).Decode(v)
}

// Delete removes key. Deleting a missing key is not an error.
func (b *Blobs) Delete(key string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(b.bucket).Delete([]byte(key))
	})
}

// Keys returns every key in the bucket.
func (b *Blobs) Keys() ([]string, error) {
	var keys []string
	err := b.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(b.bucket).ForEach(func(k, _ []byte) error {
			keys = append(keys, string(k))
			return nil
		})
	})
	return keys, err
}

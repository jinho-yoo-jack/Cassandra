// Package reportstore adapts the server's compressed blob store to report.Store.
// Report models and the headless analysis engine do not open a database.
package reportstore

import (
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage/boltstore"
)

type Store struct{ blobs *boltstore.Blobs }

var _ report.Store = (*Store)(nil)

func New(blobs *boltstore.Blobs) *Store { return &Store{blobs: blobs} }
func (s *Store) Get(name string) (*report.Report, error) {
	var r report.Report
	if err := s.blobs.Get(name, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
func (s *Store) Put(name string, r *report.Report) error { return s.blobs.Put(name, r) }
func (s *Store) Delete(name string) error                { return s.blobs.Delete(name) }
func (s *Store) Names() ([]string, error)                { return s.blobs.Keys() }

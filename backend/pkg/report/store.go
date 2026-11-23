package report

// Reader is the read-only report contract used by presentation and remediation.
type Reader interface {
	Get(name string) (*Report, error)
}

// Store persists reports without exposing the storage engine to consumers.
type Store interface {
	Reader
	Put(name string, r *Report) error
	Delete(name string) error
	Names() ([]string, error)
}

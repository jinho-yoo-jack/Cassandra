// Package rest defines the storage interfaces a resource may implement. The
// endpoint installer discovers the supported verbs by type assertion, exactly
// like k8s.io/apiserver/pkg/registry/rest.
package rest

import (
	"context"
	"io"
	"net/url"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/watch"
)

// Storage is the minimal interface every resource implements.
type Storage interface {
	// Kind is the kind of objects served by this storage.
	Kind() string
}

// ListOptions are the parsed query parameters of list and watch calls.
type ListOptions struct {
	// FieldSelector supports metadata.name=<name> only.
	FieldSelector map[string]string
	// SendInitialEvents makes a watch begin with ADDED events for every
	// existing object. Defaults to true for watch requests.
	SendInitialEvents bool
}

// Matches reports whether an object name passes the field selector.
func (o *ListOptions) Matches(name string) bool {
	if want, ok := o.FieldSelector["metadata.name"]; ok {
		return want == name
	}
	return true
}

// Getter retrieves a single object.
type Getter interface {
	Get(ctx context.Context, name string, opts url.Values) (any, error)
}

// Lister lists objects.
type Lister interface {
	List(ctx context.Context, opts *ListOptions) (any, error)
}

// Watcher streams changes.
type Watcher interface {
	Watch(ctx context.Context, opts *ListOptions) (watch.Interface, error)
}

// Creater creates an object in a collection (POST /resource).
type Creater interface {
	New() any
	Create(ctx context.Context, obj any) (any, error)
}

// NamedCreater creates against a named object, used for subresources such
// as POST /remediations/{name}/approval.
type NamedCreater interface {
	New() any
	Create(ctx context.Context, name string, obj any) (any, error)
}

// GracefulDeleter deletes an object.
type GracefulDeleter interface {
	Delete(ctx context.Context, name string) (any, error)
}

// ResourceStreamer is returned by Get when the response is not a JSON object
// (SBOM downloads, diffs). The equivalent of rest.ResourceStreamer in k8s.
type ResourceStreamer interface {
	InputStream(ctx context.Context) (stream io.ReadCloser, contentType string, filename string, err error)
}

// StreamFunc adapts a function to ResourceStreamer.
type StreamFunc func(ctx context.Context) (io.ReadCloser, string, string, error)

// InputStream implements ResourceStreamer.
func (f StreamFunc) InputStream(ctx context.Context) (io.ReadCloser, string, string, error) {
	return f(ctx)
}

// Package storage defines the persistence contract used by the registry and
// controllers, modelled after k8s.io/apiserver/pkg/storage.Interface.
package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/watch"
)

// Object is anything with ObjectMeta.
type Object interface {
	GetObjectMeta() *v1alpha1.ObjectMeta
}

// UpdateFunc computes the new state of an object from its current state.
// It runs inside the write transaction and must not perform I/O.
type UpdateFunc[T Object] func(current T) (T, error)

// Interface is a typed key/value store with watch support.
type Interface[T Object] interface {
	// Create persists a new object. Name must be set; UID, ResourceVersion
	// and CreationTimestamp are assigned by the store.
	Create(ctx context.Context, obj T) (T, error)
	Get(ctx context.Context, name string) (T, error)
	// List returns every object and the store revision it was read at.
	List(ctx context.Context) ([]T, string, error)
	// GuaranteedUpdate applies tryUpdate atomically to the current object.
	GuaranteedUpdate(ctx context.Context, name string, tryUpdate UpdateFunc[T]) (T, error)
	Delete(ctx context.Context, name string) (T, error)
	// Watch streams changes. With sendInitialEvents every existing object is
	// delivered as ADDED first, which makes list+watch race free.
	Watch(ctx context.Context, sendInitialEvents bool) (watch.Interface, error)
}

// ErrorCode classifies storage errors.
type ErrorCode int

const (
	ErrCodeNotFound ErrorCode = iota + 1
	ErrCodeExists
	ErrCodeConflict
)

// Error is a storage error carrying a code and the key it applies to.
type Error struct {
	Code ErrorCode
	Key  string
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Key, e.Msg) }

// NewNotFoundError returns an ErrCodeNotFound error.
func NewNotFoundError(key string) *Error {
	return &Error{Code: ErrCodeNotFound, Key: key, Msg: "not found"}
}

// NewExistsError returns an ErrCodeExists error.
func NewExistsError(key string) *Error {
	return &Error{Code: ErrCodeExists, Key: key, Msg: "already exists"}
}

// NewConflictError returns an ErrCodeConflict error.
func NewConflictError(key, msg string) *Error {
	return &Error{Code: ErrCodeConflict, Key: key, Msg: msg}
}

func hasCode(err error, code ErrorCode) bool {
	var se *Error
	return errors.As(err, &se) && se.Code == code
}

// IsNotFound reports whether err is a not found error.
func IsNotFound(err error) bool { return hasCode(err, ErrCodeNotFound) }

// IsExist reports whether err is an already exists error.
func IsExist(err error) bool { return hasCode(err, ErrCodeExists) }

// IsConflict reports whether err is a conflict error.
func IsConflict(err error) bool { return hasCode(err, ErrCodeConflict) }

// Package errors provides API errors that render as v1alpha1.Status, modelled
// after k8s.io/apimachinery/pkg/api/errors.
package errors

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/jinho-yoo-jack/vulngraph/pkg/api/validation/field"
	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/storage"
)

// StatusError is an error intended for consumption by a REST API client.
type StatusError struct {
	ErrStatus v1alpha1.Status
}

func (e *StatusError) Error() string { return e.ErrStatus.Message }

// Status returns the Status to serialise.
func (e *StatusError) Status() v1alpha1.Status { return e.ErrStatus }

func newStatus(code int, reason v1alpha1.StatusReason, msg string, details *v1alpha1.StatusDetails) *StatusError {
	return &StatusError{ErrStatus: v1alpha1.Status{
		TypeMeta: v1alpha1.NewTypeMeta(v1alpha1.KindStatus),
		Status:   "Failure",
		Code:     int32(code),
		Reason:   reason,
		Message:  msg,
		Details:  details,
	}}
}

// NewNotFound returns an error indicating the item is not found.
func NewNotFound(resource, name string) *StatusError {
	return newStatus(http.StatusNotFound, v1alpha1.StatusReasonNotFound,
		fmt.Sprintf("%s %q not found", resource, name), &v1alpha1.StatusDetails{Name: name, Kind: resource})
}

// NewAlreadyExists returns an error indicating the item already exists.
func NewAlreadyExists(resource, name string) *StatusError {
	return newStatus(http.StatusConflict, v1alpha1.StatusReasonAlreadyExists,
		fmt.Sprintf("%s %q already exists", resource, name), &v1alpha1.StatusDetails{Name: name, Kind: resource})
}

// NewConflict returns an error indicating the request conflicts with the
// current state of the object.
func NewConflict(resource, name string, err error) *StatusError {
	return newStatus(http.StatusConflict, v1alpha1.StatusReasonConflict,
		fmt.Sprintf("operation cannot be fulfilled on %s %q: %v", resource, name, err), &v1alpha1.StatusDetails{Name: name, Kind: resource})
}

// NewInvalid returns an error indicating the object failed validation.
func NewInvalid(kind, name string, errs field.ErrorList) *StatusError {
	causes := make([]v1alpha1.StatusCause, 0, len(errs))
	msg := fmt.Sprintf("%s %q is invalid", kind, name)
	for i, e := range errs {
		causes = append(causes, v1alpha1.StatusCause{Field: e.Field, Message: e.Detail})
		sep := ", "
		if i == 0 {
			sep = ": "
		}
		msg += sep + e.Error()
	}
	return newStatus(http.StatusUnprocessableEntity, v1alpha1.StatusReasonInvalid, msg,
		&v1alpha1.StatusDetails{Name: name, Kind: kind, Causes: causes})
}

// NewBadRequest returns an error indicating the request is malformed.
func NewBadRequest(msg string) *StatusError {
	return newStatus(http.StatusBadRequest, v1alpha1.StatusReasonBadRequest, msg, nil)
}

// NewUnauthorized returns an error indicating the request is not authenticated.
func NewUnauthorized(msg string) *StatusError {
	return newStatus(http.StatusUnauthorized, v1alpha1.StatusReasonUnauthorized, msg, nil)
}

// NewMethodNotSupported returns an error indicating the verb is not supported
// by the resource.
func NewMethodNotSupported(resource, verb string) *StatusError {
	return newStatus(http.StatusMethodNotAllowed, v1alpha1.StatusReasonMethodNotAllowed,
		fmt.Sprintf("%s is not supported on resources of kind %q", verb, resource), nil)
}

// NewInternalError returns an error indicating a server bug.
func NewInternalError(err error) *StatusError {
	return newStatus(http.StatusInternalServerError, v1alpha1.StatusReasonInternalError,
		fmt.Sprintf("internal error occurred: %v", err), nil)
}

// FromStorage converts a storage error into an API error for resource/name.
func FromStorage(err error, resource, name string) error {
	switch {
	case err == nil:
		return nil
	case storage.IsNotFound(err):
		return NewNotFound(resource, name)
	case storage.IsExist(err):
		return NewAlreadyExists(resource, name)
	case storage.IsConflict(err):
		return NewConflict(resource, name, err)
	default:
		return err
	}
}

// ReasonForError returns the reason of a StatusError, or "" for other errors.
func ReasonForError(err error) v1alpha1.StatusReason {
	var se *StatusError
	if errors.As(err, &se) {
		return se.ErrStatus.Reason
	}
	return ""
}

// IsNotFound reports whether err is a NotFound StatusError.
func IsNotFound(err error) bool { return ReasonForError(err) == v1alpha1.StatusReasonNotFound }

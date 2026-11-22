// Package handlers contains the generic HTTP handlers that operate on
// rest.Storage implementations.
package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	apierrors "github.com/jinho-yoo-jack/vulngraph/pkg/api/errors"
)

// WriteObject writes obj as JSON with the given status code.
func WriteObject(w http.ResponseWriter, code int, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	if err := enc.Encode(obj); err != nil {
		slog.Debug("[handlers] Write response failed", "err", err)
	}
}

// ErrorNegotiated writes err as a Status. Errors that are not StatusErrors
// are reported as internal errors and logged, without leaking their text to
// the client beyond the message.
func ErrorNegotiated(w http.ResponseWriter, r *http.Request, err error) {
	var se *apierrors.StatusError
	if !errors.As(err, &se) {
		slog.Error("[handlers] Unhandled error", "path", r.URL.Path, "err", err)
		se = apierrors.NewInternalError(err)
	}
	status := se.Status()
	WriteObject(w, int(status.Code), status)
}

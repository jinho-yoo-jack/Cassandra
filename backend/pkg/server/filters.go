package server

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	apierrors "github.com/jinho-yoo-jack/vulngraph/pkg/api/errors"
	"github.com/jinho-yoo-jack/vulngraph/pkg/endpoints/handlers"
	"github.com/jinho-yoo-jack/vulngraph/pkg/endpoints/request"
)

// WithRequestInfo attaches RequestInfo to every request.
func WithRequestInfo(handler http.Handler, factory *request.RequestInfoFactory) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := factory.NewRequestInfo(r)
		handler.ServeHTTP(w, r.WithContext(request.WithRequestInfo(r.Context(), info)))
	})
}

// WithPanicRecovery converts handler panics into 500 responses.
func WithPanicRecovery(handler http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				logger.Error("[server] Handler panic", "path", r.URL.Path, "panic", v, "stack", string(debug.Stack()))
				handlers.ErrorNegotiated(w, r, apierrors.NewInternalError(errPanic))
			}
		}()
		handler.ServeHTTP(w, r)
	})
}

type panicError struct{}

func (panicError) Error() string { return "handler panicked" }

var errPanic = panicError{}

// statusRecorder captures the response code while still supporting Flush,
// which watch streaming relies on.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// WithLogging logs one line per API request.
func WithLogging(handler http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		handler.ServeHTTP(rec, r)
		info, _ := request.RequestInfoFrom(r.Context())
		if info == nil || !info.IsResourceRequest {
			return
		}
		logger.Info("[server] Request",
			"verb", info.Verb, "resource", info.Resource, "subresource", info.Subresource,
			"name", info.Name, "code", rec.code, "latency", time.Since(start).Round(time.Millisecond))
	})
}

package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	apierrors "github.com/jinho-yoo-jack/Cassandra/backend/pkg/api/errors"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/rest"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/watch"
)

// maxBodyBytes bounds request bodies; API objects are small.
const maxBodyBytes = 1 << 20

// GetResource serves GET /resource/{name}[/{subresource}].
func GetResource(g rest.Getter, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		obj, err := g.Get(r.Context(), name, r.URL.Query())
		if err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		if s, ok := obj.(rest.ResourceStreamer); ok {
			streamResource(w, r, s)
			return
		}
		WriteObject(w, http.StatusOK, obj)
	}
}

func streamResource(w http.ResponseWriter, r *http.Request, s rest.ResourceStreamer) {
	stream, contentType, filename, err := s.InputStream(r.Context())
	if err != nil {
		ErrorNegotiated(w, r, err)
		return
	}
	defer stream.Close()
	w.Header().Set("Content-Type", contentType)
	if filename != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	}
	_, _ = io.Copy(w, stream)
}

// ListResource serves GET /resource.
func ListResource(l rest.Lister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts, err := parseListOptions(r)
		if err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		obj, err := l.List(r.Context(), opts)
		if err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		WriteObject(w, http.StatusOK, obj)
	}
}

// CreateResource serves POST /resource.
func CreateResource(c rest.Creater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		obj := c.New()
		if err := decodeBody(r, obj); err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		out, err := c.Create(r.Context(), obj)
		if err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		WriteObject(w, http.StatusCreated, out)
	}
}

// CreateNamedResource serves POST /resource/{name}/{subresource}.
func CreateNamedResource(c rest.NamedCreater, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		obj := c.New()
		if err := decodeBody(r, obj); err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		out, err := c.Create(r.Context(), name, obj)
		if err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		WriteObject(w, http.StatusCreated, out)
	}
}

// DeleteResource serves DELETE /resource/{name}.
func DeleteResource(d rest.GracefulDeleter, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := d.Delete(r.Context(), name)
		if err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		WriteObject(w, http.StatusOK, out)
	}
}

// WatchResource serves GET /resource?watch=true. Browsers get Server-Sent
// Events; other clients get newline delimited JSON like kube-apiserver.
func WatchResource(wr rest.Watcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts, err := parseListOptions(r)
		if err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		watcher, err := wr.Watch(r.Context(), opts)
		if err != nil {
			ErrorNegotiated(w, r, err)
			return
		}
		defer watcher.Stop()
		serveWatch(w, r, watcher)
	}
}

const heartbeatInterval = 15 * time.Second

func serveWatch(w http.ResponseWriter, r *http.Request, watcher watch.Interface) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		ErrorNegotiated(w, r, apierrors.NewInternalError(fmt.Errorf("streaming unsupported")))
		return
	}
	sse := strings.Contains(r.Header.Get("Accept"), "text/event-stream")
	if sse {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
	} else {
		w.Header().Set("Content-Type", "application/json;stream=watch")
	}
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if sse {
				_, _ = io.WriteString(w, ": ping\n\n")
				flusher.Flush()
			}
		case ev, ok := <-watcher.ResultChan():
			if !ok {
				return // watcher terminated; the client reconnects
			}
			if sse {
				_, _ = io.WriteString(w, "data: ")
			}
			if err := enc.Encode(ev); err != nil {
				return
			}
			if sse {
				_, _ = io.WriteString(w, "\n")
			}
			flusher.Flush()
		}
	}
}

func parseListOptions(r *http.Request) (*rest.ListOptions, error) {
	q := r.URL.Query()
	opts := &rest.ListOptions{FieldSelector: map[string]string{}, SendInitialEvents: true}
	if v := q.Get("sendInitialEvents"); v == "false" {
		opts.SendInitialEvents = false
	}
	if fs := q.Get("fieldSelector"); fs != "" {
		for term := range strings.SplitSeq(fs, ",") {
			k, v, ok := strings.Cut(term, "=")
			if !ok || k != "metadata.name" {
				return nil, apierrors.NewBadRequest(fmt.Sprintf("unsupported field selector %q", term))
			}
			opts.FieldSelector[k] = v
		}
	}
	return opts, nil
}

func decodeBody(r *http.Request, into any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return apierrors.NewBadRequest(fmt.Sprintf("invalid request body: %v", err))
	}
	return nil
}

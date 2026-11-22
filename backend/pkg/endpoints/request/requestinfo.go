// Package request parses API paths into RequestInfo, modelled after
// k8s.io/apiserver/pkg/endpoints/request.
package request

import (
	"context"
	"net/http"
	"strings"
)

// RequestInfo holds information parsed from the request path and method.
type RequestInfo struct {
	// IsResourceRequest is false for non-resource paths such as /healthz.
	IsResourceRequest bool
	Path              string
	// Verb is one of get, list, watch, create, update, delete.
	Verb        string
	APIPrefix   string
	APIGroup    string
	APIVersion  string
	Resource    string
	Subresource string
	Name        string
}

// RequestInfoFactory builds RequestInfo for paths below APIPrefix.
type RequestInfoFactory struct {
	APIPrefix string // "apis"
}

// NewRequestInfo parses /apis/{group}/{version}/{resource}[/{name}[/{subresource}]].
func (f *RequestInfoFactory) NewRequestInfo(req *http.Request) *RequestInfo {
	info := &RequestInfo{Path: req.URL.Path, Verb: strings.ToLower(req.Method)}

	parts := splitPath(req.URL.Path)
	if len(parts) < 4 || parts[0] != f.APIPrefix {
		return info
	}
	info.IsResourceRequest = true
	info.APIPrefix, info.APIGroup, info.APIVersion, info.Resource = parts[0], parts[1], parts[2], parts[3]
	if len(parts) > 4 {
		info.Name = parts[4]
	}
	if len(parts) > 5 {
		info.Subresource = parts[5]
	}

	switch req.Method {
	case http.MethodGet, http.MethodHead:
		switch {
		case info.Name != "":
			info.Verb = "get"
		case isWatch(req):
			info.Verb = "watch"
		default:
			info.Verb = "list"
		}
	case http.MethodPost:
		info.Verb = "create"
	case http.MethodPut:
		info.Verb = "update"
	case http.MethodDelete:
		info.Verb = "delete"
	}
	return info
}

func isWatch(req *http.Request) bool {
	v := req.URL.Query().Get("watch")
	return v == "true" || v == "1"
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

type requestInfoKey struct{}

// WithRequestInfo returns a copy of ctx carrying info.
func WithRequestInfo(ctx context.Context, info *RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

// RequestInfoFrom returns the RequestInfo stored in ctx.
func RequestInfoFrom(ctx context.Context) (*RequestInfo, bool) {
	info, ok := ctx.Value(requestInfoKey{}).(*RequestInfo)
	return info, ok
}

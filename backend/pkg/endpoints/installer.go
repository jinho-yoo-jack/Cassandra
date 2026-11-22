// Package endpoints wires rest.Storage implementations to HTTP, modelled
// after the APIInstaller in k8s.io/apiserver/pkg/endpoints.
package endpoints

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	apierrors "github.com/jinho-yoo-jack/vulngraph/pkg/api/errors"
	"github.com/jinho-yoo-jack/vulngraph/pkg/endpoints/handlers"
	"github.com/jinho-yoo-jack/vulngraph/pkg/endpoints/request"
	"github.com/jinho-yoo-jack/vulngraph/pkg/registry/rest"
)

// APIGroupVersion is a group/version and the storage for its resources.
// Storage keys are "resource" or "resource/subresource".
type APIGroupVersion struct {
	Group   string
	Version string
	Storage map[string]rest.Storage
}

// Root is the URL prefix of the group version.
func (g *APIGroupVersion) Root() string {
	return fmt.Sprintf("/apis/%s/%s", g.Group, g.Version)
}

// InstallREST registers the group version on mux.
func (g *APIGroupVersion) InstallREST(mux *http.ServeMux) {
	mux.HandleFunc("GET "+g.Root(), g.serveDiscovery)
	mux.HandleFunc(g.Root()+"/", g.serveResource)
}

func (g *APIGroupVersion) serveResource(w http.ResponseWriter, r *http.Request) {
	info, ok := request.RequestInfoFrom(r.Context())
	if !ok || !info.IsResourceRequest {
		handlers.ErrorNegotiated(w, r, apierrors.NewBadRequest("not a resource request"))
		return
	}
	key := info.Resource
	if info.Subresource != "" {
		key += "/" + info.Subresource
	}
	storage, ok := g.Storage[key]
	if !ok {
		handlers.ErrorNegotiated(w, r, apierrors.NewNotFound("resource", key))
		return
	}

	var h http.Handler
	switch info.Verb {
	case "get":
		if s, ok := storage.(rest.Getter); ok {
			h = handlers.GetResource(s, info.Name)
		}
	case "list":
		if s, ok := storage.(rest.Lister); ok {
			h = handlers.ListResource(s)
		}
	case "watch":
		if s, ok := storage.(rest.Watcher); ok {
			h = handlers.WatchResource(s)
		}
	case "create":
		switch s := storage.(type) {
		case rest.NamedCreater:
			if info.Name != "" {
				h = handlers.CreateNamedResource(s, info.Name)
			}
		case rest.Creater:
			if info.Name == "" {
				h = handlers.CreateResource(s)
			}
		}
	case "delete":
		if s, ok := storage.(rest.GracefulDeleter); ok && info.Name != "" {
			h = handlers.DeleteResource(s, info.Name)
		}
	}
	if h == nil {
		handlers.ErrorNegotiated(w, r, apierrors.NewMethodNotSupported(key, info.Verb))
		return
	}
	h.ServeHTTP(w, r)
}

// APIResource describes one resource for discovery.
type APIResource struct {
	Name  string   `json:"name"`
	Kind  string   `json:"kind"`
	Verbs []string `json:"verbs"`
}

// APIResourceList is the discovery document of a group version.
type APIResourceList struct {
	Kind         string        `json:"kind"`
	GroupVersion string        `json:"groupVersion"`
	Resources    []APIResource `json:"resources"`
}

func (g *APIGroupVersion) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	list := APIResourceList{Kind: "APIResourceList", GroupVersion: g.Group + "/" + g.Version}
	for name, s := range g.Storage {
		list.Resources = append(list.Resources, APIResource{Name: name, Kind: s.Kind(), Verbs: verbsOf(s, strings.Contains(name, "/"))})
	}
	sort.Slice(list.Resources, func(i, j int) bool { return list.Resources[i].Name < list.Resources[j].Name })
	handlers.WriteObject(w, http.StatusOK, list)
}

func verbsOf(s rest.Storage, subresource bool) []string {
	var verbs []string
	if _, ok := s.(rest.Getter); ok {
		verbs = append(verbs, "get")
	}
	if _, ok := s.(rest.Lister); ok {
		verbs = append(verbs, "list")
	}
	if _, ok := s.(rest.Watcher); ok {
		verbs = append(verbs, "watch")
	}
	if _, ok := s.(rest.Creater); ok && !subresource {
		verbs = append(verbs, "create")
	}
	if _, ok := s.(rest.NamedCreater); ok {
		verbs = append(verbs, "create")
	}
	if _, ok := s.(rest.GracefulDeleter); ok {
		verbs = append(verbs, "delete")
	}
	return verbs
}

// Package feed exposes the synchronisation state of vulnerability feeds.
package feed

import (
	"context"
	"net/url"

	apierrors "github.com/jinho-yoo-jack/vulngraph/pkg/api/errors"
	"github.com/jinho-yoo-jack/vulngraph/pkg/apis/vulngraph/v1alpha1"
	"github.com/jinho-yoo-jack/vulngraph/pkg/registry/generic"
	"github.com/jinho-yoo-jack/vulngraph/pkg/registry/rest"
	"github.com/jinho-yoo-jack/vulngraph/pkg/storage"
	"github.com/jinho-yoo-jack/vulngraph/pkg/watch"
)

// REST is read-only; feeds are written by the feed syncer.
type REST struct {
	store storage.Interface[*v1alpha1.Feed]
}

// NewREST returns the storage.
func NewREST(store storage.Interface[*v1alpha1.Feed]) *REST { return &REST{store: store} }

func (r *REST) Kind() string { return v1alpha1.KindFeed }

func (r *REST) Get(ctx context.Context, name string, _ url.Values) (any, error) {
	out, err := r.store.Get(ctx, name)
	return out, apierrors.FromStorage(err, v1alpha1.ResourceFeeds, name)
}

func (r *REST) List(ctx context.Context, opts *rest.ListOptions) (any, error) {
	items, rv, err := r.store.List(ctx)
	if err != nil {
		return nil, err
	}
	list := &v1alpha1.FeedList{TypeMeta: v1alpha1.NewTypeMeta(v1alpha1.KindFeedList), ListMeta: v1alpha1.ListMeta{ResourceVersion: rv}, Items: []v1alpha1.Feed{}}
	for _, it := range items {
		if opts.Matches(it.Name) {
			list.Items = append(list.Items, *it)
		}
	}
	return list, nil
}

func (r *REST) Watch(ctx context.Context, opts *rest.ListOptions) (watch.Interface, error) {
	return generic.Watch(ctx, r.store, opts)
}

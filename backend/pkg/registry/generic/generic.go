// Package generic holds helpers shared by resource registries.
package generic

import (
	"context"
	"crypto/rand"
	"regexp"
	"strings"

	"github.com/jinho-yoo-jack/vulngraph/pkg/registry/rest"
	"github.com/jinho-yoo-jack/vulngraph/pkg/storage"
	"github.com/jinho-yoo-jack/vulngraph/pkg/watch"
)

var (
	dns1123     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	nonDNSChars = regexp.MustCompile(`[^a-z0-9-]+`)
)

// MaxNameLength bounds object names.
const MaxNameLength = 63

// IsDNS1123Label reports whether name is a valid object name.
func IsDNS1123Label(name string) bool {
	return len(name) <= MaxNameLength && dns1123.MatchString(name)
}

// Slug lower-cases s and replaces everything that is not allowed in a name
// with dashes, truncated to at most n characters.
func Slug(s string, n int) string {
	p := strings.Trim(nonDNSChars.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(p) > n {
		p = strings.Trim(p[:n], "-")
	}
	return p
}

// GenerateName turns a free form prefix into a valid name with a random
// suffix, like metadata.generateName.
func GenerateName(prefix string) string {
	p := Slug(prefix, MaxNameLength-6)
	const alphabet = "bcdfghjklmnpqrstvwxz2456789"
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	if p == "" {
		return string(b)
	}
	return p + "-" + string(b)
}

// filteredWatch drops events whose object does not match.
type filteredWatch struct {
	src    watch.Interface
	result chan watch.Event
	match  func(obj any) bool
}

// FilterWatch returns a watch that only forwards matching events.
func FilterWatch(w watch.Interface, match func(obj any) bool) watch.Interface {
	fw := &filteredWatch{src: w, result: make(chan watch.Event), match: match}
	go func() {
		defer close(fw.result)
		for ev := range w.ResultChan() {
			if fw.match(ev.Object) {
				fw.result <- ev
			}
		}
	}()
	return fw
}

func (f *filteredWatch) ResultChan() <-chan watch.Event { return f.result }

func (f *filteredWatch) Stop() {
	f.src.Stop()
	// Drain so the forwarding goroutine can observe the closed source.
	go func() {
		for range f.result {
		}
	}()
}

// Watch opens a store watch honouring the field selector.
func Watch[T storage.Object](ctx context.Context, s storage.Interface[T], opts *rest.ListOptions) (watch.Interface, error) {
	w, err := s.Watch(ctx, opts.SendInitialEvents)
	if err != nil {
		return nil, err
	}
	if len(opts.FieldSelector) == 0 {
		return w, nil
	}
	return FilterWatch(w, func(obj any) bool {
		o, ok := obj.(storage.Object)
		return ok && opts.Matches(o.GetObjectMeta().Name)
	}), nil
}

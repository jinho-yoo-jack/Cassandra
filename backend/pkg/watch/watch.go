// Package watch is a minimal version of k8s.io/apimachinery/pkg/watch: an
// event stream plus a broadcaster that fans events out to many watchers.
package watch

import "sync"

// EventType is the type of a watch event.
type EventType string

const (
	Added    EventType = "ADDED"
	Modified EventType = "MODIFIED"
	Deleted  EventType = "DELETED"
)

// Event is one change notification.
type Event struct {
	Type   EventType `json:"type"`
	Object any       `json:"object"`
}

// Interface can be implemented by anything that knows how to watch and
// report changes.
type Interface interface {
	// ResultChan returns a channel that is closed when the watch ends, either
	// because Stop was called or because the watcher fell behind.
	ResultChan() <-chan Event
	Stop()
}

// DefaultQueueLength is how many undelivered events a watcher may buffer
// before it is considered too slow and terminated.
const DefaultQueueLength = 256

// Broadcaster distributes events to all registered watchers. Slow watchers
// are dropped instead of blocking writers, the same trade-off the kube
// watch cache makes; clients re-establish the watch.
type Broadcaster struct {
	mu       sync.Mutex
	watchers map[int64]*broadcasterWatcher
	nextID   int64
	stopped  bool
}

// NewBroadcaster returns an empty Broadcaster.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{watchers: map[int64]*broadcasterWatcher{}}
}

// WatchWithPrefix registers a watcher whose channel first yields the given
// events. prefixFn is called while holding the broadcaster lock, so no event
// published concurrently can be ordered before the prefix.
func (b *Broadcaster) WatchWithPrefix(prefixFn func() ([]Event, error)) (Interface, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	prefix, err := prefixFn()
	if err != nil {
		return nil, err
	}
	w := &broadcasterWatcher{
		id:     b.nextID,
		result: make(chan Event, len(prefix)+DefaultQueueLength),
		b:      b,
	}
	b.nextID++
	for _, e := range prefix {
		w.result <- e
	}
	if b.stopped {
		close(w.result)
		w.closed = true
		return w, nil
	}
	b.watchers[w.id] = w
	return w, nil
}

// Action publishes an event to all watchers.
func (b *Broadcaster) Action(t EventType, obj any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, w := range b.watchers {
		select {
		case w.result <- Event{Type: t, Object: obj}:
		default:
			// Watcher fell behind; terminate it so writers never block.
			delete(b.watchers, id)
			w.closeLocked()
		}
	}
}

// Shutdown terminates every watcher.
func (b *Broadcaster) Shutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	for id, w := range b.watchers {
		delete(b.watchers, id)
		w.closeLocked()
	}
}

type broadcasterWatcher struct {
	id     int64
	result chan Event
	b      *Broadcaster
	closed bool
}

func (w *broadcasterWatcher) ResultChan() <-chan Event { return w.result }

func (w *broadcasterWatcher) Stop() {
	w.b.mu.Lock()
	defer w.b.mu.Unlock()
	delete(w.b.watchers, w.id)
	w.closeLocked()
}

func (w *broadcasterWatcher) closeLocked() {
	if !w.closed {
		w.closed = true
		close(w.result)
	}
}

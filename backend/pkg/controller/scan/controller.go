// Package scan is the scan controller: it runs Pending scans and
// re-evaluates finished scans when feeds report new advisories.
package scan

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/feeds"
	scanregistry "github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/scan"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/scanner"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/watch"
)

const (
	// reevaluatePrefix marks queue keys that only re-match advisories.
	reevaluatePrefix = "reevaluate/"
	maxRetries       = 5
)

// Controller reconciles Scans.
type ScanService interface {
	Scan(context.Context, string, v1alpha1.ScanSpec, scanner.Progress) (*report.Report, error)
	Reevaluate(context.Context, *report.Report) (*report.Report, []string, error)
}

type ReportStore interface {
	report.Reader
	Put(string, *report.Report) error
}

type Controller struct {
	scans   storage.Interface[*v1alpha1.Scan]
	reports ReportStore
	scanner ScanService
	queue   workqueue.TypedRateLimitingInterface[string]
	log     *slog.Logger
	index   *index
}

var _ feeds.Sink = (*Controller)(nil)

// NewController returns a controller.
func NewController(scans storage.Interface[*v1alpha1.Scan], reports ReportStore, s ScanService, log *slog.Logger) *Controller {
	return &Controller{
		scans: scans, reports: reports, scanner: s, log: log, index: newIndex(),
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "scan"},
		),
	}
}

// Run starts workers and blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context, workers int) {
	defer c.queue.ShutDown()
	c.log.Info("[scan-controller] Starting", "workers", workers)

	if err := c.recoverInterrupted(ctx); err != nil {
		c.log.Error("[scan-controller] Recover interrupted scans failed", "err", err)
	}
	c.rebuildIndex(ctx)

	go c.watchLoop(ctx)
	for range workers {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}
	<-ctx.Done()
	c.log.Info("[scan-controller] Stopping")
}

// recoverInterrupted resets scans left Running by a previous process.
func (c *Controller) recoverInterrupted(ctx context.Context) error {
	items, _, err := c.scans.List(ctx)
	if err != nil {
		return err
	}
	for _, s := range items {
		if s.Status.Phase != v1alpha1.ScanRunning {
			continue
		}
		if _, err := c.scans.GuaranteedUpdate(ctx, s.Name, func(cur *v1alpha1.Scan) (*v1alpha1.Scan, error) {
			cur.Status.Phase, cur.Status.Message = v1alpha1.ScanPending, "Restarted after interruption"
			return cur, nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) rebuildIndex(ctx context.Context) {
	items, _, err := c.scans.List(ctx)
	if err != nil {
		c.log.Error("[scan-controller] List scans failed", "err", err)
		return
	}
	for _, s := range items {
		if s.Status.Phase != v1alpha1.ScanSucceeded {
			continue
		}
		if r, err := c.reports.Get(s.Name); err == nil {
			c.index.set(s.Name, r)
		}
	}
}

// watchLoop is a minimal informer: list+watch, enqueue keys, re-watch when
// the stream ends.
func (c *Controller) watchLoop(ctx context.Context) {
	for ctx.Err() == nil {
		w, err := c.scans.Watch(ctx, true)
		if err != nil {
			c.log.Error("[scan-controller] Watch failed", "err", err)
			time.Sleep(time.Second)
			continue
		}
		c.consume(ctx, w)
	}
}

func (c *Controller) consume(ctx context.Context, w watch.Interface) {
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.ResultChan():
			if !ok {
				return
			}
			s := ev.Object.(*v1alpha1.Scan)
			switch {
			case ev.Type == watch.Deleted:
				c.index.remove(s.Name)
			case s.Status.Phase == v1alpha1.ScanPending:
				c.queue.Add(s.Name)
			}
		}
	}
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextItem(ctx) {
	}
}

func (c *Controller) processNextItem(ctx context.Context) bool {
	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(key)

	err := c.sync(ctx, key)
	switch {
	case err == nil:
		c.queue.Forget(key)
	case c.queue.NumRequeues(key) < maxRetries && ctx.Err() == nil:
		c.log.Warn("[scan-controller] Sync failed, requeueing", "key", key, "err", err)
		c.queue.AddRateLimited(key)
	default:
		c.log.Error("[scan-controller] Dropping key", "key", key, "err", err)
		c.queue.Forget(key)
	}
	return true
}

func (c *Controller) sync(ctx context.Context, key string) error {
	if name, ok := strings.CutPrefix(key, reevaluatePrefix); ok {
		return c.reevaluate(ctx, name)
	}
	s, err := c.scans.Get(ctx, key)
	if storage.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.Status.Phase != v1alpha1.ScanPending {
		return nil
	}

	update := func(mutate func(*v1alpha1.Scan)) error {
		_, err := c.scans.GuaranteedUpdate(ctx, key, func(cur *v1alpha1.Scan) (*v1alpha1.Scan, error) {
			mutate(cur)
			return cur, nil
		})
		return err
	}
	if err := update(func(s *v1alpha1.Scan) { scanregistry.MarkRunning(s, "Starting") }); err != nil {
		return err
	}
	start := time.Now()
	rep, err := c.scanner.Scan(ctx, key, s.Spec, func(msg string) {
		if err := update(func(s *v1alpha1.Scan) { scanregistry.MarkRunning(s, msg) }); err != nil {
			c.log.Warn("[scan-controller] Progress update failed", "scan", key, "err", err)
		}
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err() // shutting down; recoverInterrupted resumes it
		}
		c.log.Warn("[scan-controller] Scan failed", "scan", key, "err", err)
		return update(func(s *v1alpha1.Scan) { scanregistry.MarkFailed(s, err) })
	}
	if err := c.reports.Put(key, rep); err != nil {
		return fmt.Errorf("store report: %w", err)
	}
	c.index.set(key, rep)
	c.log.Info("[scan-controller] Scan succeeded", "scan", key, "components", len(rep.Inventory.Components),
		"findings", len(rep.Match.Findings), "duration", time.Since(start).Round(time.Millisecond))
	return update(func(s *v1alpha1.Scan) { scanregistry.MarkSucceeded(s, rep) })
}

func (c *Controller) reevaluate(ctx context.Context, name string) error {
	s, err := c.scans.Get(ctx, name)
	if storage.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.Status.Phase != v1alpha1.ScanSucceeded {
		return nil
	}
	rep, err := c.reports.Get(name)
	if err != nil {
		return err
	}
	updated, added, err := c.scanner.Reevaluate(ctx, rep)
	if err != nil {
		return err
	}
	if err := c.reports.Put(name, updated); err != nil {
		return err
	}
	c.index.set(name, updated)
	if len(added) > 0 {
		c.log.Info("[scan-controller] New findings", "scan", name, "added", added)
	}
	_, err = c.scans.GuaranteedUpdate(ctx, name, func(cur *v1alpha1.Scan) (*v1alpha1.Scan, error) {
		now := time.Now().UTC()
		cur.Status.Summary, cur.Status.LastEvaluatedTime = updated.Summary(), &now
		if len(added) > 0 {
			v1alpha1.SetCondition(&cur.Status.Conditions, v1alpha1.Condition{
				Type: v1alpha1.ScanConditionNewFindings, Status: v1alpha1.ConditionTrue, Reason: "FeedUpdate",
				Message: "New: " + strings.Join(added, ", "), LastTransitionTime: now,
			})
		}
		return cur, nil
	})
	return err
}

// Reevaluate schedules a re-evaluation of one scan.
func (c *Controller) Reevaluate(name string) { c.queue.Add(reevaluatePrefix + name) }

// Notify implements feeds.Sink.
func (c *Controller) Notify(ch feeds.Changes) int {
	names := c.index.affected(ch)
	for _, n := range names {
		c.Reevaluate(n)
	}
	return len(names)
}

// index maps package keys and CVEs to the scans containing them.
type index struct {
	mu        sync.RWMutex
	byPackage map[feeds.PackageKey]map[string]bool
	byCVE     map[string]map[string]bool
	keysOf    map[string][]feeds.PackageKey // scan -> keys, for removal
	cvesOf    map[string][]string
}

func newIndex() *index {
	return &index{
		byPackage: map[feeds.PackageKey]map[string]bool{}, byCVE: map[string]map[string]bool{},
		keysOf: map[string][]feeds.PackageKey{}, cvesOf: map[string][]string{},
	}
}

func (x *index) set(scan string, r *report.Report) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.removeLocked(scan)
	for _, c := range r.Inventory.Components {
		for _, k := range feeds.KeysOf(c) {
			if x.byPackage[k] == nil {
				x.byPackage[k] = map[string]bool{}
			}
			x.byPackage[k][scan] = true
			x.keysOf[scan] = append(x.keysOf[scan], k)
		}
	}
	for _, v := range r.Match.Vulnerabilities {
		if v.CVE == "" {
			continue
		}
		if x.byCVE[v.CVE] == nil {
			x.byCVE[v.CVE] = map[string]bool{}
		}
		x.byCVE[v.CVE][scan] = true
		x.cvesOf[scan] = append(x.cvesOf[scan], v.CVE)
	}
}

func (x *index) remove(scan string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.removeLocked(scan)
}

func (x *index) removeLocked(scan string) {
	for _, k := range x.keysOf[scan] {
		delete(x.byPackage[k], scan)
	}
	for _, cve := range x.cvesOf[scan] {
		delete(x.byCVE[cve], scan)
	}
	delete(x.keysOf, scan)
	delete(x.cvesOf, scan)
}

func (x *index) affected(ch feeds.Changes) []string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	set := map[string]bool{}
	for _, k := range ch.Packages {
		for s := range x.byPackage[k] {
			set[s] = true
		}
	}
	for _, cve := range ch.CVEs {
		for s := range x.byCVE[cve] {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out
}

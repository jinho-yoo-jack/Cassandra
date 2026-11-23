// Package scan implements the scans resource and its graph and sbom
// subresources.
package scan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"time"

	apierrors "github.com/jinho-yoo-jack/Cassandra/backend/pkg/api/errors"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/api/validation/field"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/github"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/graph"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/generic"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/rest"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/sbom"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/watch"
)

const resource = v1alpha1.ResourceScans

// REST implements the scans collection.
type ReportRepository interface {
	report.Reader
	Delete(string) error
}

type REST struct {
	store   storage.Interface[*v1alpha1.Scan]
	reports ReportRepository
}

// NewREST returns the scans storage and its subresources.
func NewREST(store storage.Interface[*v1alpha1.Scan], reports ReportRepository) (*REST, *GraphREST, *SBOMREST) {
	return &REST{store: store, reports: reports}, &GraphREST{store: store, reports: reports}, &SBOMREST{reports: reports}
}

var (
	_ rest.Creater         = (*REST)(nil)
	_ rest.Getter          = (*REST)(nil)
	_ rest.Lister          = (*REST)(nil)
	_ rest.Watcher         = (*REST)(nil)
	_ rest.GracefulDeleter = (*REST)(nil)
)

func (r *REST) Kind() string { return v1alpha1.KindScan }
func (r *REST) New() any     { return &v1alpha1.Scan{} }

// Create validates the spec and persists a Pending scan.
func (r *REST) Create(ctx context.Context, obj any) (any, error) {
	scan := obj.(*v1alpha1.Scan)
	repo, errs := validate(scan)
	if len(errs) > 0 {
		return nil, apierrors.NewInvalid(v1alpha1.KindScan, scan.Name, errs)
	}
	if scan.Name == "" {
		scan.Name = generic.GenerateName(repo.Owner + "-" + repo.Name)
	}
	if scan.Spec.Ref == "" {
		scan.Spec.Ref = repo.Ref
	}
	scan.TypeMeta = v1alpha1.NewTypeMeta(v1alpha1.KindScan)
	scan.Status = v1alpha1.ScanStatus{Phase: v1alpha1.ScanPending, Message: "Waiting for a worker"}
	out, err := r.store.Create(ctx, scan)
	return out, apierrors.FromStorage(err, resource, scan.Name)
}

func validate(scan *v1alpha1.Scan) (github.RepoRef, field.ErrorList) {
	var errs field.ErrorList
	if scan.Name != "" && !generic.IsDNS1123Label(scan.Name) {
		errs = append(errs, field.Invalid(field.NewPath("metadata", "name"), scan.Name, "must be a lowercase RFC 1123 label"))
	}
	p := field.NewPath("spec", "repositoryURL")
	if scan.Spec.RepositoryURL == "" {
		return github.RepoRef{}, append(errs, field.Required(p, ""))
	}
	repo, err := github.ParseRepoURL(scan.Spec.RepositoryURL)
	if err != nil {
		errs = append(errs, field.Invalid(p, scan.Spec.RepositoryURL, err.Error()))
	}
	return repo, errs
}

func (r *REST) Get(ctx context.Context, name string, _ url.Values) (any, error) {
	out, err := r.store.Get(ctx, name)
	return out, apierrors.FromStorage(err, resource, name)
}

func (r *REST) List(ctx context.Context, opts *rest.ListOptions) (any, error) {
	items, rv, err := r.store.List(ctx)
	if err != nil {
		return nil, err
	}
	list := &v1alpha1.ScanList{TypeMeta: v1alpha1.NewTypeMeta(v1alpha1.KindScanList), ListMeta: v1alpha1.ListMeta{ResourceVersion: rv}, Items: []v1alpha1.Scan{}}
	for _, s := range items {
		if opts.Matches(s.Name) {
			list.Items = append(list.Items, *s)
		}
	}
	return list, nil
}

func (r *REST) Watch(ctx context.Context, opts *rest.ListOptions) (watch.Interface, error) {
	return generic.Watch(ctx, r.store, opts)
}

// Delete removes the scan and its report.
func (r *REST) Delete(ctx context.Context, name string) (any, error) {
	out, err := r.store.Delete(ctx, name)
	if err != nil {
		return nil, apierrors.FromStorage(err, resource, name)
	}
	if err := r.reports.Delete(name); err != nil {
		return nil, err
	}
	return out, nil
}

// loadReport returns the report of a succeeded scan.
func loadReport(ctx context.Context, store storage.Interface[*v1alpha1.Scan], reports report.Reader, name string) (*report.Report, error) {
	s, err := store.Get(ctx, name)
	if err != nil {
		return nil, apierrors.FromStorage(err, resource, name)
	}
	if s.Status.Phase != v1alpha1.ScanSucceeded {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("scan %q is %s; results are available once it has succeeded", name, s.Status.Phase))
	}
	r, err := reports.Get(name)
	if err != nil {
		return nil, apierrors.FromStorage(err, "reports", name)
	}
	return r, nil
}

// GraphREST serves scans/{name}/graph.
type GraphREST struct {
	store   storage.Interface[*v1alpha1.Scan]
	reports report.Reader
}

func (g *GraphREST) Kind() string { return v1alpha1.KindScanGraph }

func (g *GraphREST) Get(ctx context.Context, name string, _ url.Values) (any, error) {
	r, err := loadReport(ctx, g.store, g.reports, name)
	if err != nil {
		return nil, err
	}
	return graph.Build(name, r), nil
}

// SBOMREST serves scans/{name}/sbom?format=cyclonedx|spdx as a download.
type SBOMREST struct {
	reports report.Reader
}

func (s *SBOMREST) Kind() string { return "SBOM" }

func (s *SBOMREST) Get(ctx context.Context, name string, opts url.Values) (any, error) {
	r, err := s.reports.Get(name)
	if err != nil {
		return nil, apierrors.FromStorage(err, resource, name)
	}
	format := sbom.Format(opts.Get("format"))
	if format == "" {
		format = sbom.CycloneDX
	}
	data, err := sbom.Encode(r, format)
	if err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}
	contentType := "application/vnd.cyclonedx+json"
	if format == sbom.SPDX {
		contentType = "application/spdx+json"
	}
	filename := fmt.Sprintf("%s.%s.json", name, format)
	return rest.StreamFunc(func(context.Context) (io.ReadCloser, string, string, error) {
		return io.NopCloser(bytes.NewReader(data)), contentType, filename, nil
	}), nil
}

// MarkRunning sets the Running phase with a progress message.
func MarkRunning(s *v1alpha1.Scan, msg string) {
	if s.Status.StartTime == nil {
		now := time.Now().UTC()
		s.Status.StartTime = &now
	}
	s.Status.Phase, s.Status.Message = v1alpha1.ScanRunning, msg
}

// MarkFailed sets the Failed phase.
func MarkFailed(s *v1alpha1.Scan, err error) {
	now := time.Now().UTC()
	s.Status.Phase, s.Status.Message, s.Status.CompletionTime = v1alpha1.ScanFailed, err.Error(), &now
}

// MarkSucceeded records the outcome of a report.
func MarkSucceeded(s *v1alpha1.Scan, r *report.Report) {
	now := time.Now().UTC()
	repo := r.Repository
	s.Status.Phase, s.Status.CompletionTime, s.Status.LastEvaluatedTime = v1alpha1.ScanSucceeded, &now, &now
	s.Status.Repository, s.Status.Summary = &repo, r.Summary()
	s.Status.Message = fmt.Sprintf("%d components, %d vulnerabilities", s.Status.Summary.Components, s.Status.Summary.Vulnerabilities)
	if len(r.Match.Warnings) > 0 {
		s.Status.Message += fmt.Sprintf(" (%d warnings: %s)", len(r.Match.Warnings), r.Match.Warnings[0])
	}
}

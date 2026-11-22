// Package remediation implements the remediations resource and its
// approval, docs and diff subresources.
package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	apierrors "github.com/jinho-yoo-jack/Cassandra/backend/pkg/api/errors"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/api/validation/field"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/git"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/inventory"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/generic"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/registry/rest"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/storage"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/watch"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/workspace"
)

const resource = v1alpha1.ResourceRemediations

// REST implements the remediations collection.
type REST struct {
	store   storage.Interface[*v1alpha1.Remediation]
	scans   storage.Interface[*v1alpha1.Scan]
	reports *report.Store
}

// Storage bundles the resource and its subresources.
type Storage struct {
	Remediation *REST
	Approval    *ApprovalREST
	Docs        *DocsREST
	Diff        *DiffREST
}

// NewStorage returns the remediations storage.
func NewStorage(store storage.Interface[*v1alpha1.Remediation], scans storage.Interface[*v1alpha1.Scan], reports *report.Store, layout workspace.Layout) Storage {
	return Storage{
		Remediation: &REST{store: store, scans: scans, reports: reports},
		Approval:    &ApprovalREST{store: store},
		Docs:        &DocsREST{store: store, layout: layout},
		Diff:        &DiffREST{store: store, layout: layout},
	}
}

func (r *REST) Kind() string { return v1alpha1.KindRemediation }
func (r *REST) New() any     { return &v1alpha1.Remediation{} }

// Create validates that the finding exists and persists a Pending
// remediation. The name is derived from scan, component and vulnerability,
// so the store's uniqueness guarantees one remediation per finding.
func (r *REST) Create(ctx context.Context, obj any) (any, error) {
	rem := obj.(*v1alpha1.Remediation)
	spec := field.NewPath("spec")
	var errs field.ErrorList
	if rem.Spec.ScanName == "" {
		errs = append(errs, field.Required(spec.Child("scanName"), ""))
	}
	if rem.Spec.VulnerabilityID == "" {
		errs = append(errs, field.Required(spec.Child("vulnerabilityID"), ""))
	}
	if rem.Spec.ComponentID == "" {
		errs = append(errs, field.Required(spec.Child("componentID"), ""))
	}
	if d := rem.Spec.Deploy; d != nil && (d.Namespace == "" || d.Deployment == "" || d.Container == "") {
		errs = append(errs, field.Required(spec.Child("deploy"), "namespace, deployment and container are required"))
	}
	if len(errs) > 0 {
		return nil, apierrors.NewInvalid(v1alpha1.KindRemediation, rem.Name, errs)
	}

	scan, err := r.scans.Get(ctx, rem.Spec.ScanName)
	if err != nil {
		return nil, apierrors.FromStorage(err, v1alpha1.ResourceScans, rem.Spec.ScanName)
	}
	if scan.Status.Phase != v1alpha1.ScanSucceeded {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("scan %q has not succeeded", scan.Name))
	}
	rep, err := r.reports.Get(scan.Name)
	if err != nil {
		return nil, err
	}
	finding, ok := rep.Finding(rem.Spec.ComponentID, rem.Spec.VulnerabilityID)
	if !ok {
		return nil, apierrors.NewInvalid(v1alpha1.KindRemediation, rem.Name, field.ErrorList{
			field.Invalid(spec.Child("vulnerabilityID"), rem.Spec.VulnerabilityID, "no such finding on the component"),
		})
	}
	comp := rep.Inventory.Component(finding.ComponentID)
	vuln := rep.Match.Vulnerabilities[finding.VulnerabilityID]

	rem.Name = Name(scan.Name, comp, vuln)
	rem.TypeMeta = v1alpha1.NewTypeMeta(v1alpha1.KindRemediation)
	rem.Status = v1alpha1.RemediationStatus{
		Phase:   v1alpha1.RemediationPending,
		Message: "Waiting for a worker",
		Kind:    KindFor(comp),
		DocsID:  vuln.DisplayID(),
		Component: &v1alpha1.ComponentRef{
			Name: comp.Name, Version: comp.Version, Ecosystem: string(comp.Ecosystem),
			PURL: comp.PURL, Direct: comp.Direct, Manifests: comp.Locations,
		},
		FromVersion: comp.Version,
		BaseBranch:  rep.Repository.Branch,
		BaseCommit:  rep.Repository.Commit,
	}
	out, err := r.store.Create(ctx, rem)
	return out, apierrors.FromStorage(err, resource, rem.Name)
}

// KindFor selects the pipeline for a component.
func KindFor(c *inventory.Component) v1alpha1.RemediationKind {
	if c.Ecosystem == inventory.Process || c.Ecosystem == inventory.Image {
		return v1alpha1.RemediationImage
	}
	return v1alpha1.RemediationDependency
}

// Name is the deterministic name of the remediation of one finding.
func Name(scan string, c *inventory.Component, v *v1alpha1.Vulnerability) string {
	sum := sha256.Sum256([]byte(scan + "|" + c.ID + "|" + v.ID))
	return generic.Slug(v.DisplayID()+"-"+c.Name, generic.MaxNameLength-9) + "-" + hex.EncodeToString(sum[:4])
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
	list := &v1alpha1.RemediationList{
		TypeMeta: v1alpha1.NewTypeMeta(v1alpha1.KindRemediationList),
		ListMeta: v1alpha1.ListMeta{ResourceVersion: rv}, Items: []v1alpha1.Remediation{},
	}
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

func (r *REST) Delete(ctx context.Context, name string) (any, error) {
	out, err := r.store.Get(ctx, name)
	if err != nil {
		return nil, apierrors.FromStorage(err, resource, name)
	}
	if out.Status.Phase == v1alpha1.RemediationRunning {
		return nil, apierrors.NewConflict(resource, name, fmt.Errorf("a step is running; retry when it finishes"))
	}
	out, err = r.store.Delete(ctx, name)
	return out, apierrors.FromStorage(err, resource, name)
}

// ApprovalREST serves POST remediations/{name}/approval.
type ApprovalREST struct {
	store storage.Interface[*v1alpha1.Remediation]
}

func (a *ApprovalREST) Kind() string { return v1alpha1.KindApproval }
func (a *ApprovalREST) New() any     { return &v1alpha1.RemediationApproval{} }

// Create records the review decision. Only AwaitingReview remediations can
// be decided, and only once.
func (a *ApprovalREST) Create(ctx context.Context, name string, obj any) (any, error) {
	approval := obj.(*v1alpha1.RemediationApproval)
	if strings.TrimSpace(approval.Reviewer) == "" {
		return nil, apierrors.NewInvalid(v1alpha1.KindApproval, name, field.ErrorList{field.Required(field.NewPath("reviewer"), "")})
	}
	out, err := a.store.GuaranteedUpdate(ctx, name, func(cur *v1alpha1.Remediation) (*v1alpha1.Remediation, error) {
		if cur.Status.Phase != v1alpha1.RemediationAwaitingReview {
			return nil, apierrors.NewConflict(resource, name, fmt.Errorf("remediation is %s, not %s", cur.Status.Phase, v1alpha1.RemediationAwaitingReview))
		}
		now := time.Now().UTC()
		cond := v1alpha1.Condition{Status: v1alpha1.ConditionTrue, Reason: "Reviewed", Message: approval.Comment, LastTransitionTime: now}
		if approval.Approved {
			cond.Type = v1alpha1.RemediationConditionApproved
			cur.Status.Phase, cur.Status.Message = v1alpha1.RemediationApproved, "Approved by "+approval.Reviewer
		} else {
			cond.Type = v1alpha1.RemediationConditionDenied
			cur.Status.Phase, cur.Status.Message = v1alpha1.RemediationDenied, "Denied by "+approval.Reviewer
		}
		v1alpha1.SetCondition(&cur.Status.Conditions, cond)
		cur.Status.Reviewer, cur.Status.ReviewComment = approval.Reviewer, approval.Comment
		if step := cur.Status.Step(v1alpha1.StepReview); step != nil {
			step.State, step.Message, step.CompletionTime = v1alpha1.StepSucceeded, cur.Status.Message, &now
			if !approval.Approved {
				step.State = v1alpha1.StepFailed
			}
		}
		return cur, nil
	})
	if err != nil {
		var se *apierrors.StatusError
		if errors.As(err, &se) {
			return nil, se
		}
		return nil, apierrors.FromStorage(err, resource, name)
	}
	return out, nil
}

// DocsREST serves GET remediations/{name}/docs: the generated markdown files
// as they currently are in the work branch.
type DocsREST struct {
	store  storage.Interface[*v1alpha1.Remediation]
	layout workspace.Layout
}

func (d *DocsREST) Kind() string { return v1alpha1.KindDocs }

func (d *DocsREST) Get(ctx context.Context, name string, _ url.Values) (any, error) {
	rem, err := d.store.Get(ctx, name)
	if err != nil {
		return nil, apierrors.FromStorage(err, resource, name)
	}
	docs := &v1alpha1.RemediationDocs{TypeMeta: v1alpha1.NewTypeMeta(v1alpha1.KindDocs), Files: []v1alpha1.DocFile{}}
	root := d.layout.Remediation(name)
	for _, p := range rem.Status.Docs {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			continue
		}
		docs.Files = append(docs.Files, v1alpha1.DocFile{Path: p, Content: string(data)})
	}
	return docs, nil
}

// DiffREST serves GET remediations/{name}/diff as text/x-diff.
type DiffREST struct {
	store  storage.Interface[*v1alpha1.Remediation]
	layout workspace.Layout
}

func (d *DiffREST) Kind() string { return "Diff" }

func (d *DiffREST) Get(ctx context.Context, name string, _ url.Values) (any, error) {
	rem, err := d.store.Get(ctx, name)
	if err != nil {
		return nil, apierrors.FromStorage(err, resource, name)
	}
	dir := d.layout.Remediation(name)
	if rem.Status.BaseCommit == "" {
		return nil, apierrors.NewBadRequest("no working copy yet")
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return nil, apierrors.NewBadRequest("working copy is not available")
	}
	diff, err := git.Open(dir, "").Diff(ctx, rem.Status.BaseCommit)
	if err != nil {
		return nil, err
	}
	return rest.StreamFunc(func(context.Context) (io.ReadCloser, string, string, error) {
		return io.NopCloser(strings.NewReader(diff)), "text/x-diff; charset=utf-8", "", nil
	}), nil
}

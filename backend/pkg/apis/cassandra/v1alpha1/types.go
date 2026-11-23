package v1alpha1

import "time"

// TypeMeta describes an individual object in an API response or request.
type TypeMeta struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
}

// ObjectMeta is metadata that all persisted resources must have.
type ObjectMeta struct {
	Name              string            `json:"name"`
	UID               string            `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	Generation        int64             `json:"generation,omitempty"`
	CreationTimestamp time.Time         `json:"creationTimestamp,omitzero"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
}

// GetObjectMeta lets every type embedding ObjectMeta satisfy storage.Object.
func (m *ObjectMeta) GetObjectMeta() *ObjectMeta { return m }

// ListMeta describes metadata that synthetic list resources carry.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// ConditionStatus is the status of a condition.
type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)

// Condition contains details for one aspect of the current state of an object.
type Condition struct {
	Type               string          `json:"type"`
	Status             ConditionStatus `json:"status"`
	Reason             string          `json:"reason,omitempty"`
	Message            string          `json:"message,omitempty"`
	LastTransitionTime time.Time       `json:"lastTransitionTime,omitzero"`
}

// SetCondition adds or replaces the condition of the same type. The
// transition time only moves when the status actually changes.
func SetCondition(conditions *[]Condition, c Condition) {
	for i := range *conditions {
		cur := &(*conditions)[i]
		if cur.Type != c.Type {
			continue
		}
		if cur.Status != c.Status {
			cur.LastTransitionTime = c.LastTransitionTime
		}
		cur.Status, cur.Reason, cur.Message = c.Status, c.Reason, c.Message
		return
	}
	*conditions = append(*conditions, c)
}

// FindCondition returns the condition of the given type, or nil.
func FindCondition(conditions []Condition, conditionType string) *Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

// Scan analyses a GitHub repository: it builds an SBOM, a code/dependency
// graph and matches every component against vulnerability feeds.
type Scan struct {
	TypeMeta
	ObjectMeta `json:"metadata"`

	Spec   ScanSpec   `json:"spec"`
	Status ScanStatus `json:"status,omitzero"`
}

// ScanSpec is the desired state of a Scan.
type ScanSpec struct {
	// RepositoryURL is a GitHub repository, e.g. https://github.com/owner/repo.
	RepositoryURL string `json:"repositoryURL"`
	// Ref is a branch, tag or commit. Empty means the default branch.
	Ref string `json:"ref,omitempty"`
}

// ScanPhase is a coarse summary of where a Scan is in its lifecycle.
type ScanPhase string

const (
	ScanPending   ScanPhase = "Pending"
	ScanRunning   ScanPhase = "Running"
	ScanSucceeded ScanPhase = "Succeeded"
	ScanFailed    ScanPhase = "Failed"
)

// Scan condition types.
const (
	// ScanConditionNewFindings is True when a feed update found
	// vulnerabilities after the initial scan completed.
	ScanConditionNewFindings = "NewFindings"
)

// ScanStatus is the observed state of a Scan.
type ScanStatus struct {
	Phase   ScanPhase `json:"phase,omitempty"`
	Message string    `json:"message,omitempty"`

	Repository *RepositoryInfo `json:"repository,omitempty"`
	Summary    *ScanSummary    `json:"summary,omitempty"`

	StartTime         *time.Time `json:"startTime,omitempty"`
	CompletionTime    *time.Time `json:"completionTime,omitempty"`
	LastEvaluatedTime *time.Time `json:"lastEvaluatedTime,omitempty"`

	Conditions []Condition `json:"conditions,omitempty"`
}

// RepositoryInfo identifies the exact source that was scanned.
type RepositoryInfo struct {
	Owner  string `json:"owner"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Branch string `json:"branch,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// ScanSummary aggregates the scan result.
type ScanSummary struct {
	Projects             int              `json:"projects"`
	Packages             int              `json:"packages"`
	Components           int              `json:"components"`
	VulnerableComponents int              `json:"vulnerableComponents"`
	Vulnerabilities      int              `json:"vulnerabilities"`
	BySeverity           map[Severity]int `json:"bySeverity,omitempty"`
	KnownExploited       int              `json:"knownExploited"`
}

// ScanList is a list of Scans.
type ScanList struct {
	TypeMeta
	ListMeta `json:"metadata"`
	Items    []Scan `json:"items"`
}

// ---------------------------------------------------------------------------
// Vulnerability (read-only, served from the vulnerability cache)
// ---------------------------------------------------------------------------

// Severity is a normalised qualitative severity.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
	SeverityUnknown  Severity = "UNKNOWN"
)

// Rank orders severities; higher is worse.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityNone:
		return 1
	default:
		return 0
	}
}

// Vulnerability is a normalised advisory, keyed by its OSV or CVE id.
type Vulnerability struct {
	TypeMeta

	ID         string            `json:"id"`
	Aliases    []string          `json:"aliases,omitempty"`
	CVE        string            `json:"cve,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	Details    string            `json:"details,omitempty"`
	Severity   Severity          `json:"severity"`
	CVSS       *CVSS             `json:"cvss,omitempty"`
	EPSS       *EPSS             `json:"epss,omitempty"`
	KEV        *KEV              `json:"kev,omitempty"`
	CWEs       []string          `json:"cwes,omitempty"`
	Published  time.Time         `json:"published,omitzero"`
	Modified   time.Time         `json:"modified,omitzero"`
	Withdrawn  *time.Time        `json:"withdrawn,omitempty"`
	References []Reference       `json:"references,omitempty"`
	Affected   []AffectedPackage `json:"affected,omitempty"`
	// Source is the feed the record came from: osv, nvd or github.
	Source string `json:"source"`
}

// DisplayID is the CVE id when one exists, otherwise the native id.
func (v *Vulnerability) DisplayID() string {
	if v.CVE != "" {
		return v.CVE
	}
	return v.ID
}

// CVSS is a CVSS base score.
type CVSS struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
}

// EPSS is the FIRST Exploit Prediction Scoring System result.
type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date,omitempty"`
}

// KEV is a CISA Known Exploited Vulnerabilities catalog entry.
type KEV struct {
	DateAdded       string `json:"dateAdded"`
	DueDate         string `json:"dueDate,omitempty"`
	RequiredAction  string `json:"requiredAction,omitempty"`
	KnownRansomware bool   `json:"knownRansomware,omitempty"`
}

// Reference is a link to more information.
type Reference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url"`
}

// AffectedPackage lists the vulnerable version ranges of one package.
type AffectedPackage struct {
	// Ecosystem is an OSV ecosystem name, or "CPE" for NVD matches where Name
	// is "vendor:product".
	Ecosystem string          `json:"ecosystem"`
	Name      string          `json:"name"`
	Ranges    []AffectedRange `json:"ranges,omitempty"`
}

// AffectedRange is one introduced→fixed interval.
type AffectedRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"lastAffected,omitempty"`
}

// Finding binds a vulnerability to a component of a scan.
type Finding struct {
	ComponentID     string `json:"componentID"`
	VulnerabilityID string `json:"vulnerabilityID"`
	// FixedVersion is the lowest version that fixes this component, empty if
	// no fix exists yet.
	FixedVersion string `json:"fixedVersion,omitempty"`
	// Remediation is human readable guidance for this specific component.
	Remediation string `json:"remediation,omitempty"`
}

// ---------------------------------------------------------------------------
// ScanGraph (scans/{name}/graph subresource)
// ---------------------------------------------------------------------------

// NodeKind is the kind of a graph node.
type NodeKind string

const (
	NodeRepository NodeKind = "repository"
	NodeProject    NodeKind = "project"
	NodePackage    NodeKind = "package"
	NodeLibrary    NodeKind = "library"
	NodeImage      NodeKind = "image"
	NodeProcess    NodeKind = "process"
)

// EdgeKind is the relation an edge represents.
type EdgeKind string

const (
	EdgeContains EdgeKind = "contains"
	EdgeImports  EdgeKind = "imports"
	EdgeDepends  EdgeKind = "depends"
	EdgeRuns     EdgeKind = "runs"
)

// ScanGraph is the code and dependency graph of a scan.
type ScanGraph struct {
	TypeMeta
	ObjectMeta `json:"metadata"`

	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// GraphNode is one node of a ScanGraph.
type GraphNode struct {
	ID        string   `json:"id"`
	Kind      NodeKind `json:"kind"`
	Label     string   `json:"label"`
	Version   string   `json:"version,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	PURL      string   `json:"purl,omitempty"`
	Path      string   `json:"path,omitempty"`
	Language  string   `json:"language,omitempty"`
	Direct    bool     `json:"direct,omitempty"`
	Dev       bool     `json:"dev,omitempty"`
	// Severity is the worst severity among Findings.
	Severity Severity      `json:"severity,omitempty"`
	Findings []NodeFinding `json:"findings,omitempty"`
	// FixTarget is the version a remediation of this node upgrades to.
	FixTarget string `json:"fixTarget,omitempty"`
	// OnVulnerablePath marks nodes from which a vulnerable component is
	// reachable, so clients can render only the paths that matter.
	OnVulnerablePath bool `json:"onVulnerablePath,omitempty"`
}

// NodeFinding is the per-node summary used for hover cards.
type NodeFinding struct {
	VulnerabilityID string   `json:"vulnerabilityID"`
	DisplayID       string   `json:"displayID"`
	Summary         string   `json:"summary,omitempty"`
	Severity        Severity `json:"severity"`
	Score           float64  `json:"score,omitempty"`
	FixedVersion    string   `json:"fixedVersion,omitempty"`
	KnownExploited  bool     `json:"knownExploited,omitempty"`
	EPSS            float64  `json:"epss,omitempty"`
	Remediation     string   `json:"remediation,omitempty"`
}

// GraphEdge is one edge of a ScanGraph.
type GraphEdge struct {
	ID               string   `json:"id"`
	Source           string   `json:"source"`
	Target           string   `json:"target"`
	Kind             EdgeKind `json:"kind"`
	OnVulnerablePath bool     `json:"onVulnerablePath,omitempty"`
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

// Remediation drives one vulnerability fix through
// branch → fix → test scenarios → test → review → approval → PR (and for
// container images: build → runtime test → deploy).
type Remediation struct {
	TypeMeta
	ObjectMeta `json:"metadata"`

	Spec   RemediationSpec   `json:"spec"`
	Status RemediationStatus `json:"status,omitzero"`
}

// RemediationSpec is the desired state of a Remediation.
type RemediationSpec struct {
	ScanName        string `json:"scanName"`
	VulnerabilityID string `json:"vulnerabilityID"`
	ComponentID     string `json:"componentID"`
	// TargetVersion overrides the computed fixed version.
	TargetVersion string `json:"targetVersion,omitempty"`
	// Deploy is where a fixed container image is rolled out. Optional.
	Deploy *DeployTarget `json:"deploy,omitempty"`
}

// DeployTarget is a Kubernetes workload whose container image is replaced.
type DeployTarget struct {
	Context    string `json:"context,omitempty"`
	Namespace  string `json:"namespace"`
	Deployment string `json:"deployment"`
	Container  string `json:"container"`
}

// RemediationKind selects the pipeline.
type RemediationKind string

const (
	RemediationDependency RemediationKind = "Dependency"
	RemediationImage      RemediationKind = "Image"
)

// RemediationPhase is a coarse summary of a Remediation.
type RemediationPhase string

const (
	RemediationPending        RemediationPhase = "Pending"
	RemediationRunning        RemediationPhase = "Running"
	RemediationAwaitingReview RemediationPhase = "AwaitingReview"
	RemediationApproved       RemediationPhase = "Approved"
	RemediationCompleted      RemediationPhase = "Completed"
	RemediationDenied         RemediationPhase = "Denied"
	RemediationFailed         RemediationPhase = "Failed"
)

// IsTerminal reports whether no further reconciliation will happen.
func (p RemediationPhase) IsTerminal() bool {
	return p == RemediationCompleted || p == RemediationDenied || p == RemediationFailed
}

// Remediation condition types.
const (
	RemediationConditionApproved    = "Approved"
	RemediationConditionDenied      = "Denied"
	RemediationConditionTestsPassed = "TestsPassed"
)

// StepName names a pipeline step.
type StepName string

const (
	StepCreateBranch       StepName = "CreateBranch"
	StepApplyFix           StepName = "ApplyFix"
	StepWriteTestScenarios StepName = "WriteTestScenarios"
	StepBuildImage         StepName = "BuildImage"
	StepTest               StepName = "Test"
	StepReview             StepName = "Review"
	StepDeploy             StepName = "Deploy"
	StepPullRequest        StepName = "PullRequest"
)

// StepState is the state of one step.
type StepState string

const (
	StepPending   StepState = "Pending"
	StepRunning   StepState = "Running"
	StepSucceeded StepState = "Succeeded"
	StepFailed    StepState = "Failed"
	StepSkipped   StepState = "Skipped"
	StepWaiting   StepState = "Waiting"
)

// RemediationStep is the observed state of one pipeline step.
type RemediationStep struct {
	Name           StepName   `json:"name"`
	State          StepState  `json:"state"`
	Message        string     `json:"message,omitempty"`
	Log            string     `json:"log,omitempty"`
	StartTime      *time.Time `json:"startTime,omitempty"`
	CompletionTime *time.Time `json:"completionTime,omitempty"`
}

// TestResultStatus is the outcome of one test scenario.
type TestResultStatus string

const (
	TestPassed  TestResultStatus = "Passed"
	TestFailed  TestResultStatus = "Failed"
	TestSkipped TestResultStatus = "Skipped"
)

// TestResult is the outcome of one scenario from test-scenarios.md.
type TestResult struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Status   TestResultStatus `json:"status"`
	Detail   string           `json:"detail,omitempty"`
	Duration string           `json:"duration,omitempty"`
}

// ComponentRef summarises the component being fixed.
type ComponentRef struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	PURL      string   `json:"purl"`
	Direct    bool     `json:"direct"`
	Manifests []string `json:"manifests,omitempty"`
}

// RemediationStatus is the observed state of a Remediation.
type RemediationStatus struct {
	Phase   RemediationPhase `json:"phase,omitempty"`
	Message string           `json:"message,omitempty"`
	Kind    RemediationKind  `json:"kind,omitempty"`

	// DocsID is the directory under docs/cve, the CVE id when available.
	DocsID      string        `json:"docsID,omitempty"`
	Component   *ComponentRef `json:"component,omitempty"`
	FromVersion string        `json:"fromVersion,omitempty"`
	ToVersion   string        `json:"toVersion,omitempty"`

	BaseBranch string `json:"baseBranch,omitempty"`
	BaseCommit string `json:"baseCommit,omitempty"`
	Branch     string `json:"branch,omitempty"`
	Commit     string `json:"commit,omitempty"`

	Steps       []RemediationStep `json:"steps,omitempty"`
	Docs        []string          `json:"docs,omitempty"`
	TestResults []TestResult      `json:"testResults,omitempty"`

	Image          string `json:"image,omitempty"`
	PullRequestURL string `json:"pullRequestURL,omitempty"`
	Reviewer       string `json:"reviewer,omitempty"`
	ReviewComment  string `json:"reviewComment,omitempty"`

	Conditions []Condition `json:"conditions,omitempty"`
}

// Step returns the step with the given name, or nil.
func (s *RemediationStatus) Step(name StepName) *RemediationStep {
	for i := range s.Steps {
		if s.Steps[i].Name == name {
			return &s.Steps[i]
		}
	}
	return nil
}

// RemediationList is a list of Remediations.
type RemediationList struct {
	TypeMeta
	ListMeta `json:"metadata"`
	Items    []Remediation `json:"items"`
}

// RemediationApproval is the body of POST remediations/{name}/approval,
// modelled after CertificateSigningRequest approval.
type RemediationApproval struct {
	TypeMeta
	Approved bool   `json:"approved"`
	Reviewer string `json:"reviewer"`
	Comment  string `json:"comment,omitempty"`
}

// RemediationDocs is the content of docs/cve/<id>/*.md in the work branch.
type RemediationDocs struct {
	TypeMeta
	Files []DocFile `json:"files"`
}

// DocFile is one generated document.
type DocFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ---------------------------------------------------------------------------
// Feed
// ---------------------------------------------------------------------------

// Feed reports the synchronisation state of one vulnerability source.
type Feed struct {
	TypeMeta
	ObjectMeta `json:"metadata"`

	Status FeedStatus `json:"status,omitzero"`
}

// FeedStatus is the observed state of a Feed.
type FeedStatus struct {
	Source          string               `json:"source"`
	Mode            string               `json:"mode"`
	Interval        string               `json:"interval,omitempty"`
	LastSyncTime    *time.Time           `json:"lastSyncTime,omitempty"`
	LastSuccessTime *time.Time           `json:"lastSuccessTime,omitempty"`
	LastError       string               `json:"lastError,omitempty"`
	Processed       int64                `json:"processed"`
	Matched         int64                `json:"matched"`
	Cursors         map[string]time.Time `json:"cursors,omitempty"`
}

// FeedList is a list of Feeds.
type FeedList struct {
	TypeMeta
	ListMeta `json:"metadata"`
	Items    []Feed `json:"items"`
}

// ---------------------------------------------------------------------------
// Status (errors)
// ---------------------------------------------------------------------------

// StatusReason is a machine readable error reason.
type StatusReason string

const (
	StatusReasonNotFound         StatusReason = "NotFound"
	StatusReasonAlreadyExists    StatusReason = "AlreadyExists"
	StatusReasonConflict         StatusReason = "Conflict"
	StatusReasonInvalid          StatusReason = "Invalid"
	StatusReasonBadRequest       StatusReason = "BadRequest"
	StatusReasonMethodNotAllowed StatusReason = "MethodNotAllowed"
	StatusReasonInternalError    StatusReason = "InternalError"
	StatusReasonUnauthorized     StatusReason = "Unauthorized"
)

// Status is returned for calls that don't return other objects, chiefly errors.
type Status struct {
	TypeMeta
	Status  string         `json:"status"`
	Message string         `json:"message,omitempty"`
	Reason  StatusReason   `json:"reason,omitempty"`
	Details *StatusDetails `json:"details,omitempty"`
	Code    int32          `json:"code"`
}

// StatusDetails carries additional information about a Status.
type StatusDetails struct {
	Name   string        `json:"name,omitempty"`
	Kind   string        `json:"kind,omitempty"`
	Causes []StatusCause `json:"causes,omitempty"`
}

// StatusCause is one field-level cause of an Invalid error.
type StatusCause struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

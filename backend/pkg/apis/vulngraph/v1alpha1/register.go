// Package v1alpha1 is the v1alpha1 version of the vulngraph.io API group.
//
// Objects follow the Kubernetes API conventions: every top-level object
// carries TypeMeta and ObjectMeta, desired state lives in Spec and observed
// state in Status.
package v1alpha1

const (
	// GroupName is the API group served by vulngraph-apiserver.
	GroupName = "vulngraph.io"
	// Version is the API version of this package.
	Version = "v1alpha1"
	// SchemeGroupVersion is the apiVersion written into every object.
	SchemeGroupVersion = GroupName + "/" + Version
)

// Resource names served under /apis/vulngraph.io/v1alpha1.
const (
	ResourceScans           = "scans"
	ResourceRemediations    = "remediations"
	ResourceVulnerabilities = "vulnerabilities"
	ResourceFeeds           = "feeds"
)

// Kinds.
const (
	KindScan            = "Scan"
	KindScanList        = "ScanList"
	KindScanGraph       = "ScanGraph"
	KindRemediation     = "Remediation"
	KindRemediationList = "RemediationList"
	KindApproval        = "RemediationApproval"
	KindDocs            = "RemediationDocs"
	KindVulnerability   = "Vulnerability"
	KindFeed            = "Feed"
	KindFeedList        = "FeedList"
	KindStatus          = "Status"
)

// NewTypeMeta returns TypeMeta for kind in this group version.
func NewTypeMeta(kind string) TypeMeta {
	return TypeMeta{APIVersion: SchemeGroupVersion, Kind: kind}
}

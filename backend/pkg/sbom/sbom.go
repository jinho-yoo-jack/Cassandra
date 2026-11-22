// Package sbom serialises scan reports as CycloneDX 1.6 (with embedded
// vulnerabilities, i.e. a VEX-capable BOM) and SPDX 2.3 JSON.
package sbom

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/jinho-yoo-jack/vulngraph/pkg/inventory"
	"github.com/jinho-yoo-jack/vulngraph/pkg/report"
	"github.com/jinho-yoo-jack/vulngraph/pkg/vulndb/nvd"
)

// Format is an SBOM output format.
type Format string

const (
	CycloneDX Format = "cyclonedx"
	SPDX      Format = "spdx"
)

// ToolName and ToolVersion identify the generator.
var (
	ToolName    = "vulngraph"
	ToolVersion = "0.1.0"
)

// Encode renders the report in the given format.
func Encode(r *report.Report, f Format) ([]byte, error) {
	switch f {
	case CycloneDX, "":
		return encodeCycloneDX(r)
	case SPDX:
		return encodeSPDX(r)
	}
	return nil, fmt.Errorf("unsupported SBOM format %q", f)
}

const rootRef = "repository"

func encodeCycloneDX(r *report.Report) ([]byte, error) {
	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + uuid()
	bom.Metadata = &cdx.Metadata{
		Timestamp: r.GeneratedAt.UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeApplication, Name: ToolName, Version: ToolVersion,
		}}},
		Component: &cdx.Component{
			BOMRef: rootRef, Type: cdx.ComponentTypeApplication,
			Name: r.Repository.Owner + "/" + r.Repository.Name, Version: r.Repository.Commit,
			ExternalReferences: &[]cdx.ExternalReference{{Type: cdx.ERTypeVCS, URL: r.Repository.URL}},
		},
	}

	var comps []cdx.Component
	for _, p := range r.Inventory.Projects {
		comps = append(comps, cdx.Component{
			BOMRef: p.ID, Type: cdx.ComponentTypeApplication, Name: p.Name,
			Properties: &[]cdx.Property{{Name: "vulngraph:manifest", Value: p.Manifest}},
		})
	}
	for _, c := range r.Inventory.Components {
		cc := cdx.Component{
			BOMRef: c.ID, Type: cdxType(c), Name: c.Name, Version: c.Version, PackageURL: c.PURL,
			Properties: &[]cdx.Property{
				{Name: "vulngraph:ecosystem", Value: string(c.Ecosystem)},
				{Name: "vulngraph:direct", Value: strconv.FormatBool(c.Direct)},
				{Name: "vulngraph:locations", Value: strings.Join(c.Locations, ",")},
			},
		}
		if c.Dev {
			cc.Scope = cdx.ScopeOptional
		} else {
			cc.Scope = cdx.ScopeRequired
		}
		if len(c.CPEs) > 0 && c.Version != "" {
			cc.CPE = nvd.CPEName(c.CPEs[0], c.Version)
		}
		comps = append(comps, cc)
	}
	bom.Components = &comps

	children := map[string][]string{rootRef: nil}
	for _, p := range r.Inventory.Projects {
		children[rootRef] = append(children[rootRef], p.ID)
	}
	for _, d := range r.Inventory.Dependencies {
		children[d.From] = append(children[d.From], d.To)
	}
	var deps []cdx.Dependency
	for _, ref := range append([]string{rootRef}, refsOf(r)...) {
		on := children[ref]
		deps = append(deps, cdx.Dependency{Ref: ref, Dependencies: &on})
	}
	bom.Dependencies = &deps

	var vulns []cdx.Vulnerability
	for _, f := range r.Match.Findings {
		v := r.Match.Vulnerabilities[f.VulnerabilityID]
		cv := cdx.Vulnerability{
			BOMRef:         f.ComponentID + "#" + v.ID,
			ID:             v.DisplayID(),
			Source:         &cdx.Source{Name: strings.ToUpper(v.Source)},
			Description:    v.Summary,
			Detail:         v.Details,
			Recommendation: f.Remediation,
			Affects:        &[]cdx.Affects{{Ref: f.ComponentID}},
		}
		if v.CVSS != nil && v.CVSS.Score > 0 {
			score := v.CVSS.Score
			cv.Ratings = &[]cdx.VulnerabilityRating{{
				Score: &score, Severity: cdx.Severity(strings.ToLower(string(v.Severity))),
				Method: cdx.ScoringMethodCVSSv31, Vector: v.CVSS.Vector,
			}}
		}
		if cwes := cweIDs(v.CWEs); len(cwes) > 0 {
			cv.CWEs = &cwes
		}
		var advisories []cdx.Advisory
		for _, ref := range v.References {
			advisories = append(advisories, cdx.Advisory{URL: ref.URL})
		}
		if len(advisories) > 0 {
			cv.Advisories = &advisories
		}
		var props []cdx.Property
		if v.KEV != nil {
			props = append(props, cdx.Property{Name: "cisa:kev:dateAdded", Value: v.KEV.DateAdded})
		}
		if v.EPSS != nil {
			props = append(props, cdx.Property{Name: "first:epss", Value: strconv.FormatFloat(v.EPSS.Score, 'f', 5, 64)})
		}
		if f.FixedVersion != "" {
			props = append(props, cdx.Property{Name: "vulngraph:fixedVersion", Value: f.FixedVersion})
		}
		if len(props) > 0 {
			cv.Properties = &props
		}
		vulns = append(vulns, cv)
	}
	if len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}

	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).SetPretty(true).EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func refsOf(r *report.Report) []string {
	refs := make([]string, 0, len(r.Inventory.Projects)+len(r.Inventory.Components))
	for _, p := range r.Inventory.Projects {
		refs = append(refs, p.ID)
	}
	for _, c := range r.Inventory.Components {
		refs = append(refs, c.ID)
	}
	return refs
}

func cdxType(c *inventory.Component) cdx.ComponentType {
	switch c.Type {
	case inventory.TypeContainer:
		return cdx.ComponentTypeContainer
	case inventory.TypeApplication:
		return cdx.ComponentTypeApplication
	}
	return cdx.ComponentTypeLibrary
}

func cweIDs(cwes []string) []int {
	var out []int
	for _, c := range cwes {
		if n, err := strconv.Atoi(strings.TrimPrefix(c, "CWE-")); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ---------------------------------------------------------------------------
// SPDX 2.3
// ---------------------------------------------------------------------------

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	PrimaryPurpose   string            `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

var spdxIDInvalid = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

func encodeSPDX(r *report.Report) ([]byte, error) {
	name := r.Repository.Owner + "/" + r.Repository.Name
	doc := spdxDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: name,
		DocumentNamespace: fmt.Sprintf("https://vulngraph.io/spdx/%s-%s", spdxIDInvalid.ReplaceAllString(name, "-"), uuid()),
		CreationInfo: spdxCreationInfo{
			Created:  r.GeneratedAt.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: " + ToolName + "-" + ToolVersion},
		},
	}
	ids := map[string]string{}
	spdxID := func(ref string) string {
		if id, ok := ids[ref]; ok {
			return id
		}
		id := fmt.Sprintf("SPDXRef-%d-%s", len(ids), strings.Trim(spdxIDInvalid.ReplaceAllString(ref, "-"), "-"))
		ids[ref] = id
		return id
	}
	pkg := func(ref, name, version, purpose string) spdxPackage {
		return spdxPackage{
			Name: name, SPDXID: spdxID(ref), VersionInfo: version, DownloadLocation: "NOASSERTION",
			LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION",
			PrimaryPurpose: purpose,
		}
	}

	root := pkg(rootRef, name, r.Repository.Commit, "APPLICATION")
	root.DownloadLocation = "git+" + r.Repository.URL
	doc.Packages = append(doc.Packages, root)
	doc.Relationships = append(doc.Relationships, spdxRelationship{"SPDXRef-DOCUMENT", "DESCRIBES", root.SPDXID})
	for _, p := range r.Inventory.Projects {
		doc.Packages = append(doc.Packages, pkg(p.ID, p.Name, "", "APPLICATION"))
		doc.Relationships = append(doc.Relationships, spdxRelationship{root.SPDXID, "CONTAINS", spdxID(p.ID)})
	}
	for _, c := range r.Inventory.Components {
		purpose := "LIBRARY"
		switch c.Type {
		case inventory.TypeContainer:
			purpose = "CONTAINER"
		case inventory.TypeApplication:
			purpose = "APPLICATION"
		}
		p := pkg(c.ID, c.Name, c.Version, purpose)
		p.ExternalRefs = append(p.ExternalRefs, spdxExternalRef{"PACKAGE-MANAGER", "purl", c.PURL})
		if len(c.CPEs) > 0 && c.Version != "" {
			p.ExternalRefs = append(p.ExternalRefs, spdxExternalRef{"SECURITY", "cpe23Type", nvd.CPEName(c.CPEs[0], c.Version)})
		}
		for _, f := range r.FindingsFor(c.ID) {
			v := r.Match.Vulnerabilities[f.VulnerabilityID]
			p.ExternalRefs = append(p.ExternalRefs, spdxExternalRef{"SECURITY", "advisory", "https://osv.dev/vulnerability/" + v.ID})
		}
		doc.Packages = append(doc.Packages, p)
	}
	for _, d := range r.Inventory.Dependencies {
		rel := "DEPENDS_ON"
		if c := r.Inventory.Component(d.To); c != nil && c.Dev {
			rel = "DEV_DEPENDENCY_OF"
			doc.Relationships = append(doc.Relationships, spdxRelationship{spdxID(d.To), rel, spdxID(d.From)})
			continue
		}
		doc.Relationships = append(doc.Relationships, spdxRelationship{spdxID(d.From), rel, spdxID(d.To)})
	}
	return json.MarshalIndent(doc, "", "  ")
}

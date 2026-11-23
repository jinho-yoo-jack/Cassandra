package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/apis/cassandra/v1alpha1"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/report"
	"github.com/jinho-yoo-jack/Cassandra/backend/pkg/sbom"
)

func sarifLevel(severity v1alpha1.Severity) string {
	if severity.Rank() >= v1alpha1.SeverityHigh.Rank() {
		return "error"
	}
	if severity == v1alpha1.SeverityLow || severity == v1alpha1.SeverityNone {
		return "note"
	}
	return "warning"
}

func encodeSARIF(r *report.Report) ([]byte, error) {
	rules := []any{}
	indices := map[string]int{}
	results := []any{}
	for _, f := range r.Match.Findings {
		v, c := r.Match.Vulnerabilities[f.VulnerabilityID], r.Inventory.Component(f.ComponentID)
		id := v.DisplayID()
		index, exists := indices[id]
		if !exists {
			index = len(rules)
			indices[id] = index
			props := map[string]any{"tags": []string{"security", "dependency"}}
			if v.CVSS != nil {
				props["security-severity"] = strconv.FormatFloat(v.CVSS.Score, 'f', 1, 64)
			}
			text := v.Summary
			if text == "" {
				text = id
			}
			rules = append(rules, map[string]any{"id": id, "shortDescription": map[string]string{"text": text}, "properties": props})
		}
		locations := []any{}
		paths := append([]string(nil), c.Locations...)
		slices.Sort(paths)
		for _, p := range slices.Compact(paths) {
			p = strings.ReplaceAll(p, "\\", "/")
			clean := path.Clean(p)
			if clean == "." || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
				continue
			}
			u := (&url.URL{Path: clean}).EscapedPath()
			locations = append(locations, map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": u, "uriBaseId": "%SRCROOT%"}}})
		}
		message := fmt.Sprintf("%s@%s: %s", c.Name, c.Version, v.Summary)
		if f.FixedVersion != "" {
			message += "; fixed in " + f.FixedVersion
		}
		sum := sha256.Sum256([]byte(f.ComponentID + "|" + id + "|" + strings.Join(paths, "|")))
		result := map[string]any{"ruleId": id, "ruleIndex": index, "level": sarifLevel(v.Severity), "message": map[string]string{"text": message}, "partialFingerprints": map[string]string{"cassandra/component/v1": hex.EncodeToString(sum[:])}}
		if len(locations) > 0 {
			result["locations"] = locations
		}
		results = append(results, result)
	}
	invocation := map[string]any{"executionSuccessful": len(r.Match.Warnings) == 0 && len(r.Inventory.Projects) > 0}
	if len(r.Match.Warnings) > 0 {
		notifications := []any{}
		for _, warning := range r.Match.Warnings {
			notifications = append(notifications, map[string]any{"level": "warning", "message": map[string]string{"text": warning}})
		}
		invocation["toolExecutionNotifications"] = notifications
	}
	return json.MarshalIndent(map[string]any{
		"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "Cassandra", "version": sbom.ToolVersion, "informationUri": "https://github.com/jinho-yoo-jack/Cassandra", "rules": rules}}, "results": results, "invocations": []any{invocation}}},
	}, "", "  ")
}

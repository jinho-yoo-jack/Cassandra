// Typed endpoint facade. Keep the existing import surface for callers.
import type { Feed, List, Remediation, Scan, ScanGraph, Vulnerability } from "./api-types";
import { request, requestText } from "./http";

export type * from "./api-types";
export { ApiError } from "./http";

export const API_ROOT = "/apis/cassandra.io/v1alpha1";

export const api = {
  listScans: () => request<List<Scan>>(`${API_ROOT}/scans`),
  getScan: (name: string) => request<Scan>(`${API_ROOT}/scans/${name}`),
  createScan: (repositoryURL: string, ref?: string) =>
    request<Scan>(`${API_ROOT}/scans`, { method: "POST", body: JSON.stringify({ spec: { repositoryURL, ref } }) }),
  deleteScan: (name: string) => request<Scan>(`${API_ROOT}/scans/${name}`, { method: "DELETE" }),
  getGraph: (name: string) => request<ScanGraph>(`${API_ROOT}/scans/${name}/graph`),
  sbomURL: (name: string, format: "cyclonedx" | "spdx") => `${API_ROOT}/scans/${name}/sbom?format=${format}`,

  getVulnerability: (id: string) => request<Vulnerability>(`${API_ROOT}/vulnerabilities/${encodeURIComponent(id)}`),

  listRemediations: () => request<List<Remediation>>(`${API_ROOT}/remediations`),
  getRemediation: (name: string) => request<Remediation>(`${API_ROOT}/remediations/${name}`),
  createRemediation: (spec: Remediation["spec"]) =>
    request<Remediation>(`${API_ROOT}/remediations`, { method: "POST", body: JSON.stringify({ spec }) }),
  deleteRemediation: (name: string) => request<Remediation>(`${API_ROOT}/remediations/${name}`, { method: "DELETE" }),
  approve: (name: string, approved: boolean, reviewer: string, comment: string) =>
    request<Remediation>(`${API_ROOT}/remediations/${name}/approval`, {
      method: "POST",
      body: JSON.stringify({ approved, reviewer, comment }),
    }),
  getDocs: (name: string) => request<{ files: { path: string; content: string }[] }>(`${API_ROOT}/remediations/${name}/docs`),
  getDiff: (name: string) => requestText(`${API_ROOT}/remediations/${name}/diff`),

  listFeeds: () => request<List<Feed>>(`${API_ROOT}/feeds`),
};

/** watchURL builds the Server-Sent Events URL of a watch. */
export function watchURL(resource: string, name?: string): string {
  const q = new URLSearchParams({ watch: "true" });
  if (name) q.set("fieldSelector", `metadata.name=${name}`);
  return `${API_ROOT}/${resource}?${q}`;
}

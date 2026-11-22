// Typed client for /apis/vulngraph.io/v1alpha1. Types mirror
// backend/pkg/apis/vulngraph/v1alpha1.

export const API_ROOT = "/apis/vulngraph.io/v1alpha1";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN";

export interface ObjectMeta {
  name: string;
  uid?: string;
  resourceVersion?: string;
  creationTimestamp?: string;
}

export interface Condition {
  type: string;
  status: "True" | "False" | "Unknown";
  reason?: string;
  message?: string;
  lastTransitionTime?: string;
}

export type ScanPhase = "Pending" | "Running" | "Succeeded" | "Failed";

export interface Scan {
  metadata: ObjectMeta;
  spec: { repositoryURL: string; ref?: string };
  status: {
    phase?: ScanPhase;
    message?: string;
    repository?: { owner: string; name: string; url: string; branch?: string; commit?: string };
    summary?: {
      projects: number;
      packages: number;
      components: number;
      vulnerableComponents: number;
      vulnerabilities: number;
      bySeverity?: Partial<Record<Severity, number>>;
      knownExploited: number;
    };
    startTime?: string;
    completionTime?: string;
    lastEvaluatedTime?: string;
    conditions?: Condition[];
  };
}

export type NodeKind = "repository" | "project" | "package" | "library" | "image" | "process";

export interface NodeFinding {
  vulnerabilityID: string;
  displayID: string;
  summary?: string;
  severity: Severity;
  score?: number;
  fixedVersion?: string;
  knownExploited?: boolean;
  epss?: number;
  remediation?: string;
}

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  version?: string;
  ecosystem?: string;
  purl?: string;
  path?: string;
  language?: string;
  direct?: boolean;
  dev?: boolean;
  severity?: Severity;
  findings?: NodeFinding[];
  onVulnerablePath?: boolean;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: "contains" | "imports" | "depends" | "runs";
  onVulnerablePath?: boolean;
}

export interface ScanGraph {
  metadata: ObjectMeta;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Vulnerability {
  id: string;
  aliases?: string[];
  cve?: string;
  summary?: string;
  details?: string;
  severity: Severity;
  cvss?: { version: string; vector: string; score: number };
  epss?: { score: number; percentile: number; date?: string };
  kev?: { dateAdded: string; dueDate?: string; requiredAction?: string; knownRansomware?: boolean };
  cwes?: string[];
  published?: string;
  modified?: string;
  references?: { type?: string; url: string }[];
  source: string;
}

export type RemediationPhase =
  | "Pending"
  | "Running"
  | "AwaitingReview"
  | "Approved"
  | "Completed"
  | "Denied"
  | "Failed";

export type StepState = "Pending" | "Running" | "Succeeded" | "Failed" | "Skipped" | "Waiting";

export interface RemediationStep {
  name: string;
  state: StepState;
  message?: string;
  log?: string;
  startTime?: string;
  completionTime?: string;
}

export interface TestResult {
  id: string;
  title: string;
  status: "Passed" | "Failed" | "Skipped";
  detail?: string;
  duration?: string;
}

export interface DeployTarget {
  context?: string;
  namespace: string;
  deployment: string;
  container: string;
}

export interface Remediation {
  metadata: ObjectMeta;
  spec: {
    scanName: string;
    vulnerabilityID: string;
    componentID: string;
    targetVersion?: string;
    deploy?: DeployTarget;
  };
  status: {
    phase?: RemediationPhase;
    message?: string;
    kind?: "Dependency" | "Image";
    docsID?: string;
    component?: { name: string; version: string; ecosystem: string; purl: string; direct: boolean; manifests?: string[] };
    fromVersion?: string;
    toVersion?: string;
    baseBranch?: string;
    baseCommit?: string;
    branch?: string;
    commit?: string;
    steps?: RemediationStep[];
    docs?: string[];
    testResults?: TestResult[];
    image?: string;
    pullRequestURL?: string;
    reviewer?: string;
    reviewComment?: string;
    conditions?: Condition[];
  };
}

export interface Feed {
  metadata: ObjectMeta;
  status: {
    source: string;
    mode: "pull" | "push";
    interval?: string;
    lastSyncTime?: string;
    lastSuccessTime?: string;
    lastError?: string;
    processed: number;
    matched: number;
  };
}

export interface List<T> {
  metadata: { resourceVersion?: string };
  items: T[];
}

export interface Status {
  kind: "Status";
  status: "Failure";
  message: string;
  reason?: string;
  code: number;
  details?: { name?: string; kind?: string; causes?: { field?: string; message: string }[] };
}

export class ApiError extends Error {
  readonly status: Status;
  constructor(status: Status) {
    super(status.message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}), ...init?.headers },
  });
  const text = await res.text();
  if (!res.ok) {
    let status: Status;
    try {
      status = JSON.parse(text) as Status;
    } catch {
      status = { kind: "Status", status: "Failure", message: text || res.statusText, code: res.status };
    }
    throw new ApiError(status);
  }
  return (text ? JSON.parse(text) : undefined) as T;
}

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
  getDiff: async (name: string) => {
    const res = await fetch(`${API_ROOT}/remediations/${name}/diff`);
    if (!res.ok) throw new ApiError((await res.json()) as Status);
    return res.text();
  },

  listFeeds: () => request<List<Feed>>(`${API_ROOT}/feeds`),
};

export interface WatchEvent<T> {
  type: "ADDED" | "MODIFIED" | "DELETED";
  object: T;
}

/** watchURL builds the Server-Sent Events URL of a watch. */
export function watchURL(resource: string, name?: string): string {
  const q = new URLSearchParams({ watch: "true" });
  if (name) q.set("fieldSelector", `metadata.name=${name}`);
  return `${API_ROOT}/${resource}?${q}`;
}

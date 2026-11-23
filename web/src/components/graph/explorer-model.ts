import type { GraphEdge, GraphNode, ScanGraph, NodeFinding, Severity } from "@/lib/api-types";

export interface RiskFilters {
  minSeverity: Severity;
  kevOnly: boolean;
  search: string;
  showCode: boolean;
  showDev: boolean;
}
export interface RiskRow {
  node: GraphNode;
  findings: NodeFinding[];
  severity: Severity;
  kev: boolean;
  epss?: number;
  fixable: boolean;
}
export type ExplorerMode = "overview" | "vulnerable" | "direct" | "all" | "path";
export interface GraphIndex { graph: ScanGraph; byId: Map<string, GraphNode>; incoming: Map<string, string[]>; outgoing: Map<string, string[]>; members: Map<string, Set<string>>; orphanFindings: number; orphanComponents: number; }
export interface GroupSummary { members: number; vulnerableComponents: number; findings: number; }
export interface Projection { nodes: GraphNode[]; edges: GraphEdge[]; onPath: Map<string, Severity>; }
/** One indexed traversal, cycle-safe and linear in the visited subgraph. */
export function closure(adjacency: Map<string, string[]>, seeds: Iterable<string>): Set<string> {
  const found = new Set(seeds), queue = [...found];
  for (let i = 0; i < queue.length; i++) {
    for (const next of adjacency.get(queue[i]!) ?? []) {
      if (!found.has(next)) { found.add(next); queue.push(next); }
    }
  }
  return found;
}
export function indexGraph(graph: ScanGraph): GraphIndex {
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  const incoming = new Map<string, string[]>(), outgoing = new Map<string, string[]>();
  for (const e of graph.edges) {
    if (!byId.has(e.source) || !byId.has(e.target)) continue;
    incoming.set(e.target, [...(incoming.get(e.target) ?? []), e.source]);
    outgoing.set(e.source, [...(outgoing.get(e.source) ?? []), e.target]);
  }
  const members = new Map<string, Set<string>>(), assigned = new Set<string>();
  for (const n of graph.nodes) {
    if (n.kind !== "repository" && n.kind !== "project") continue;
    const descendants = closure(outgoing, [n.id]);
    const ids = new Set([...descendants].filter(id => { const kind = byId.get(id)?.kind; return kind !== "repository" && kind !== "project"; }));
    members.set(n.id, ids);
    if (n.kind === "project") for (const id of ids) assigned.add(id);
  }
  const orphan = graph.nodes.filter(n => n.findings?.length && !assigned.has(n.id));
  return { graph, byId, incoming, outgoing, members, orphanComponents: orphan.length, orphanFindings: orphan.reduce((sum, n) => sum + n.findings!.length, 0) };
}
function subset(index: GraphIndex, ids: Set<string>): Projection {
  return { nodes: index.graph.nodes.filter(n => ids.has(n.id)), edges: index.graph.edges.filter(e => ids.has(e.source) && ids.has(e.target)), onPath: new Map() };
}
export function projectGraph(index: GraphIndex, mode: ExplorerMode, expanded: Set<string>, selected?: string): Projection {
  if (mode === "path" && selected && index.byId.has(selected)) return subset(index, closure(index.incoming, [selected]));
  if (mode === "all") return subset(index, new Set(index.byId.keys()));
  if (mode === "vulnerable") return subset(index, new Set(index.graph.nodes.filter(n => n.findings?.length).map(n => n.id)));
  const scaffolding = index.graph.nodes.filter(n => n.kind === "repository" || n.kind === "project");
  const ids = new Set(scaffolding.map(n => n.id));
  if (mode === "direct") {
    const risks = index.graph.nodes.filter(n => n.findings?.length).map(n => n.id);
    for (const id of closure(index.incoming, risks)) ids.add(id);
    for (const n of index.graph.nodes) if (n.direct || n.kind === "package") ids.add(n.id);
    for (const e of index.graph.edges) if (e.kind === "runs" && index.byId.get(e.source)?.direct) ids.add(e.target);
  } else {
    // Only an expanded *visible* branch exposes children; collapsed ancestors win.
    const queue = [...ids];
    for (let i = 0; i < queue.length; i++) {
      const id = queue[i]!;
      if (!expanded.has(id)) continue;
      for (const child of index.outgoing.get(id) ?? []) if (!ids.has(child)) { ids.add(child); queue.push(child); }
    }
  }
  return subset(index, ids);
}
export function summarizeGroups(index: GraphIndex, rows: RiskRow[]): Map<string, GroupSummary> {
  const risks = new Map(rows.map(r => [r.node.id, r]));
  return new Map([...index.members].map(([id, members]) => {
    const matched = [...members].flatMap(member => risks.has(member) ? [risks.get(member)!] : []);
    return [id, { members: members.size, vulnerableComponents: matched.length, findings: matched.reduce((sum, r) => sum + r.findings.length, 0) }];
  }));
}
/** Filtering never changes layout input; callers retain positions from base. */
export function filterProjection(index: GraphIndex, base: Projection, rows: RiskRow[], mode: ExplorerMode, active: boolean): Projection {
  if (!active && mode !== "vulnerable") return base;
  if (mode === "path") return base;
  const matches = new Set(rows.map(r => r.node.id));
  const keep = mode === "vulnerable" ? matches : closure(index.incoming, matches);
  const nodes = base.nodes.filter(n => keep.has(n.id)), ids = new Set(nodes.map(n => n.id));
  return { nodes, edges: base.edges.filter(e => ids.has(e.source) && ids.has(e.target)), onPath: new Map() };
}
export function validSelection(index: GraphIndex, rows: RiskRow[], selected: string | undefined, filters: RiskFilters): string | undefined {
  const node = selected ? index.byId.get(selected) : undefined;
  if (!node || (!filters.showDev && node.dev) || (!filters.showCode && node.kind === "package")) return undefined;
  const active = filters.search.trim() !== "" || filters.kevOnly || filters.minSeverity !== "UNKNOWN";
  return (node.findings?.length || active) && !rows.some(r => r.node.id === selected) ? undefined : selected;
}

const ranks: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1, UNKNOWN: 0 };
const compareText = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
export function rankRisks(nodes: GraphNode[], filters: RiskFilters): RiskRow[] {
  const query = filters.search.trim().toLowerCase();
  const rows: RiskRow[] = [];
  for (const node of nodes) {
    if ((!filters.showDev && node.dev) || (!filters.showCode && node.kind === "package")) continue;
    const componentMatches = [node.label, node.version, node.id, node.purl, node.path].some(v => v?.toLowerCase().includes(query));
    const findings = (node.findings ?? []).filter(f => ranks[f.severity] >= ranks[filters.minSeverity]
      && (!filters.kevOnly || f.knownExploited)
      && (!query || componentMatches || [f.displayID, f.vulnerabilityID, f.summary].some(v => v?.toLowerCase().includes(query))));
    if (!findings.length) continue;
    const severity = findings.reduce((s, f) => ranks[f.severity] > ranks[s] ? f.severity : s, "UNKNOWN" as Severity);
    const scores = findings.flatMap(f => f.epss !== undefined && Number.isFinite(f.epss) ? [f.epss] : []);
    rows.push({ node, findings, severity, kev: findings.some(f => f.knownExploited), epss: scores.length ? Math.max(...scores) : undefined, fixable: findings.some(f => !!f.fixedVersion) });
  }
  return rows.sort((a, b) => Number(b.kev) - Number(a.kev) || ranks[b.severity] - ranks[a.severity]
    || (b.epss ?? -1) - (a.epss ?? -1) || Number(b.fixable) - Number(a.fixable)
    || compareText(a.node.label, b.node.label) || compareText(a.node.version ?? "", b.node.version ?? "") || compareText(a.node.id, b.node.id));
}

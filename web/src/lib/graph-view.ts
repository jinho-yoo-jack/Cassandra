import type { ElkNode } from "elkjs/lib/elk.bundled.js";
import type { GraphEdge, GraphNode, ScanGraph, Severity } from "./api";
import type { ViewMode } from "./graph-store";
import { severityRank } from "./utils";

export interface ViewOptions {
  view: ViewMode;
  showCode: boolean;
  showDev: boolean;
  minSeverity: Severity;
}

export const NODE_WIDTH = 236;
export const NODE_HEIGHT = 58;

/** maxSeverity of a node, considering only findings at or above min. */
export function nodeSeverity(n: GraphNode, min: Severity): Severity | undefined {
  let best: Severity | undefined;
  for (const f of n.findings ?? []) {
    if (severityRank[f.severity] < severityRank[min]) continue;
    if (!best || severityRank[f.severity] > severityRank[best]) best = f.severity;
  }
  return best;
}

/**
 * vulnerablePaths maps every node from which a finding at or above min is
 * reachable to the worst such severity, walking edges backwards like the
 * server does.
 */
export function vulnerablePaths(g: ScanGraph, min: Severity): Map<string, Severity> {
  const incoming = new Map<string, string[]>();
  for (const e of g.edges) {
    const list = incoming.get(e.target) ?? [];
    list.push(e.source);
    incoming.set(e.target, list);
  }
  const worst = new Map<string, Severity>();
  const queue: string[] = [];
  for (const n of g.nodes) {
    const sev = nodeSeverity(n, min);
    if (sev) {
      worst.set(n.id, sev);
      queue.push(n.id);
    }
  }
  // Re-visit a node whenever a worse severity reaches it.
  while (queue.length > 0) {
    const cur = queue.shift()!;
    const sev = worst.get(cur)!;
    for (const src of incoming.get(cur) ?? []) {
      const prev = worst.get(src);
      if (!prev || severityRank[sev] > severityRank[prev]) {
        worst.set(src, sev);
        queue.push(src);
      }
    }
  }
  return worst;
}

/** visibleGraph applies the toolbar filters. */
export function visibleGraph(g: ScanGraph, o: ViewOptions): { nodes: GraphNode[]; edges: GraphEdge[]; onPath: Map<string, Severity> } {
  const onPath = vulnerablePaths(g, o.minSeverity);
  const direct = new Set(g.nodes.filter((n) => n.direct).map((n) => n.id));
  // Processes run by directly referenced images count as direct.
  const runsFromDirect = new Set(g.edges.filter((e) => e.kind === "runs" && direct.has(e.source)).map((e) => e.target));
  const keep = (n: GraphNode): boolean => {
    if (n.kind === "package" && !o.showCode) return false;
    if (n.dev && !o.showDev) return false;
    switch (n.kind) {
      case "repository":
      case "project":
        return true;
      case "package":
        return o.view !== "vulnerable" || onPath.has(n.id);
    }
    if (o.view === "all") return true;
    if (onPath.has(n.id)) return true;
    return o.view === "direct" && (n.direct === true || runsFromDirect.has(n.id));
  };
  const nodes = g.nodes.filter(keep);
  const ids = new Set(nodes.map((n) => n.id));
  const edges = g.edges.filter((e) => ids.has(e.source) && ids.has(e.target));
  return { nodes, edges, onPath };
}

// ELK is ~1.5 MB; load it with the first graph instead of the app shell.
let elk: Promise<{ layout: (g: ElkNode) => Promise<ElkNode> }> | undefined;
function getElk() {
  elk ??= import("elkjs/lib/elk.bundled.js").then(({ default: ELK }) => new ELK());
  return elk;
}

/** layout positions nodes left to right: repository → projects → code → libraries. */
export async function layout(nodes: GraphNode[], edges: GraphEdge[]): Promise<Map<string, { x: number; y: number }>> {
  const graph: ElkNode = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.spacing.nodeNode": "18",
      "elk.layered.spacing.nodeNodeBetweenLayers": "90",
      "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
      "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
      "elk.separateConnectedComponents": "true",
    },
    children: nodes.map((n) => ({ id: n.id, width: NODE_WIDTH, height: NODE_HEIGHT })),
    edges: edges.map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  };
  const result = await (await getElk()).layout(graph);
  const positions = new Map<string, { x: number; y: number }>();
  for (const c of result.children ?? []) positions.set(c.id, { x: c.x ?? 0, y: c.y ?? 0 });
  return positions;
}

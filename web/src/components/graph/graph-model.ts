import { type Edge, MarkerType, type Node } from "@xyflow/react";
import type { GraphNode, Severity } from "@/lib/api-types";
import { NODE_WIDTH, NODE_HEIGHT, nodeSeverity, type visibleGraph } from "@/lib/graph-view";
import { severityClass, severityRank } from "@/lib/utils";

export type FlowNodeData = {
  node: GraphNode;
  severity?: Severity;
  findingCount: number;
  dimmed: boolean;
  highlighted: boolean;
  summary?: { members: number; vulnerableComponents: number; findings: number };
  expanded?: boolean;
  childCount?: number;
  vertical?: boolean;
  onExpand?: (id: string) => void;
};
export type FlowNode = Node<FlowNodeData, "vg">;

type VisibleGraph = ReturnType<typeof visibleGraph>;

/** Build presentation data independently of layout scheduling and React state. */
export function buildFlowGraph(
  visible: VisibleGraph,
  positions: ReadonlyMap<string, { x: number; y: number }>,
  minSeverity: Severity,
): { nodes: FlowNode[]; edges: Edge[] } {
  const sevOf = new Map(visible.nodes.map((n) => [n.id, nodeSeverity(n, minSeverity)]));
  const nodes: FlowNode[] = visible.nodes.map((n) => ({
    id: n.id,
    type: "vg",
    width: NODE_WIDTH,
    height: NODE_HEIGHT,
    position: positions.get(n.id) ?? { x: 0, y: 0 },
    data: {
      node: n,
      severity: sevOf.get(n.id),
      findingCount: (n.findings ?? []).filter((f) => severityRank[f.severity] >= severityRank[minSeverity]).length,
      dimmed: false,
      highlighted: false,
    },
  }));
  const edges = visible.edges.map((e) => {
    // Colour by the worst severity reachable through the target.
    const pathSev = visible.onPath.get(e.target);
    const hot = pathSev !== undefined && e.kind !== "contains";
    const stroke = hot ? severityClass[pathSev].stroke : undefined;
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      animated: false,
      style: {
        stroke,
        strokeWidth: hot ? 2 : 1,
        strokeDasharray: e.kind === "imports" ? "5 4" : undefined,
        opacity: hot ? 0.95 : 0.45,
      },
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: stroke },
    } satisfies Edge;
  });
  return { nodes, edges };
}

/** Return ancestors and descendants along edge direction, not sibling branches. */
export function connected(edges: Edge[], id: string): Set<string> {
  const out = new Set([id]);
  for (const forward of [true, false]) {
    const queue = [id];
    while (queue.length) {
      const cur = queue.shift()!;
      for (const e of edges) {
        const [from, to] = forward ? [e.source, e.target] : [e.target, e.source];
        if (from === cur && !out.has(to)) {
          out.add(to);
          queue.push(to);
        }
      }
    }
  }
  return out;
}

/** Preserve unchanged node identities while applying selection/search display. */
export function decorateNodes(nodes: FlowNode[], edges: Edge[], selected: string | undefined, search: string): FlowNode[] {
  const keep = selected ? connected(edges, selected) : undefined;
  const q = search.trim().toLowerCase();
  return nodes.map((n) => {
    const dimmed = keep ? !keep.has(n.id) : false;
    const highlighted = q !== "" && (n.data.node.label.toLowerCase().includes(q) || (n.data.node.purl ?? "").toLowerCase().includes(q));
    return n.data.dimmed === dimmed && n.data.highlighted === highlighted ? n : { ...n, data: { ...n.data, dimmed, highlighted } };
  });
}

/** Navigation matches labels only; highlighting above also matches purls. */
export function searchHits(nodes: FlowNode[], search: string): { id: string }[] {
  const q = search.trim().toLowerCase();
  return nodes.filter((n) => n.data.node.label.toLowerCase().includes(q)).map((n) => ({ id: n.id }));
}

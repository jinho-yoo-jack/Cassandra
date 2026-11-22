import {
  Background,
  Controls,
  type Edge,
  MarkerType,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";
import { LoaderCircle, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import type { ScanGraph, Severity } from "@/lib/api";
import { useGraphStore, type ViewMode } from "@/lib/graph-store";
import { layout, nodeSeverity, visibleGraph } from "@/lib/graph-view";
import { cn, SEVERITIES, severityClass, severityLabel, severityRank } from "@/lib/utils";
import { type FlowNode, nodeTypes } from "./graph-node";
import { ScanContext } from "./node-hover-content";

export function ScanGraphView({ scanName, graph }: { scanName: string; graph: ScanGraph }) {
  return (
    <ScanContext value={scanName}>
      <ReactFlowProvider>
        <GraphCanvas graph={graph} />
      </ReactFlowProvider>
    </ScanContext>
  );
}

/** ancestorsAndDescendants returns every node connected to id along edge direction. */
function connected(edges: Edge[], id: string): Set<string> {
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

function GraphCanvas({ graph }: { graph: ScanGraph }) {
  const { view, showCode, showDev, minSeverity, search, selected, select } = useGraphStore();
  const visible = useMemo(() => visibleGraph(graph, { view, showCode, showDev, minSeverity }), [graph, view, showCode, showDev, minSeverity]);
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [laying, setLaying] = useState(true);
  const { fitView } = useReactFlow();

  useEffect(() => {
    let cancelled = false;
    setLaying(true);
    layout(visible.nodes, visible.edges).then((pos) => {
      if (cancelled) return;
      const sevOf = new Map(visible.nodes.map((n) => [n.id, nodeSeverity(n, minSeverity)]));
      setNodes(
        visible.nodes.map((n) => ({
          id: n.id,
          type: "vg",
          position: pos.get(n.id) ?? { x: 0, y: 0 },
          data: {
            node: n,
            severity: sevOf.get(n.id),
            findingCount: (n.findings ?? []).filter((f) => severityRank[f.severity] >= severityRank[minSeverity]).length,
            dimmed: false,
            highlighted: false,
          },
        })),
      );
      setEdges(
        visible.edges.map((e) => {
          // Colour by the worst severity reachable through the target.
          const pathSev = visible.onPath.get(e.target);
          const hot = pathSev !== undefined && e.kind !== "contains";
          const stroke = hot ? severityClass[pathSev].stroke : undefined;
          return {
            id: e.id,
            source: e.source,
            target: e.target,
            animated: hot && (pathSev === "CRITICAL" || pathSev === "HIGH"),
            style: {
              stroke,
              strokeWidth: hot ? 2 : 1,
              strokeDasharray: e.kind === "imports" ? "5 4" : undefined,
              opacity: hot ? 0.95 : 0.45,
            },
            markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: stroke },
          } satisfies Edge;
        }),
      );
      setLaying(false);
      requestAnimationFrame(() => fitView({ padding: 0.12, duration: 300 }));
    });
    return () => {
      cancelled = true;
    };
  }, [visible, minSeverity, setNodes, setEdges, fitView]);

  // Selection dims everything not connected to the selected node.
  useEffect(() => {
    const keep = selected ? connected(edges, selected) : undefined;
    const q = search.trim().toLowerCase();
    setNodes((ns) =>
      ns.map((n) => {
        const dimmed = keep ? !keep.has(n.id) : false;
        const highlighted = q !== "" && (n.data.node.label.toLowerCase().includes(q) || (n.data.node.purl ?? "").toLowerCase().includes(q));
        return n.data.dimmed === dimmed && n.data.highlighted === highlighted ? n : { ...n, data: { ...n.data, dimmed, highlighted } };
      }),
    );
  }, [selected, search, edges, setNodes]);

  const focusSearch = () => {
    const q = search.trim().toLowerCase();
    const hits = nodes.filter((n) => n.data.node.label.toLowerCase().includes(q)).map((n) => ({ id: n.id }));
    if (hits.length) fitView({ nodes: hits, padding: 0.4, duration: 400, maxZoom: 1.4 });
  };

  return (
    <div className="relative h-full w-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        onNodeClick={(_, n) => select(selected === n.id ? undefined : n.id)}
        onPaneClick={() => select(undefined)}
        minZoom={0.05}
        maxZoom={2}
        nodesConnectable={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={20} size={1} />
        <Controls showInteractive={false} position="bottom-right" />
        <MiniMap
          pannable
          zoomable
          position="top-right"
          nodeColor={(n) => {
            const sev = (n as FlowNode).data.severity;
            return sev ? severityClass[sev].stroke : "var(--muted-foreground)";
          }}
          bgColor="var(--card)"
          maskColor="color-mix(in oklch, var(--background) 65%, transparent)"
          className="!rounded-md !border"
        />
      </ReactFlow>

      <Toolbar total={graph.nodes.length} shown={visible.nodes.length} onSearch={focusSearch} />
      <Legend />
      {laying && (
        <div className="absolute inset-0 flex items-center justify-center bg-canvas/60 backdrop-blur-[1px]">
          <div className="flex items-center gap-2 rounded-md border bg-card px-3 py-2 text-sm shadow">
            <LoaderCircle className="size-4 animate-spin" /> 그래프 배치 중… ({visible.nodes.length}개 노드)
          </div>
        </div>
      )}
    </div>
  );
}

const views: { value: ViewMode; label: string; hint: string }[] = [
  { value: "vulnerable", label: "취약 경로", hint: "취약 컴포넌트로 이어지는 경로만" },
  { value: "direct", label: "직접 의존성", hint: "코드·직접 의존성 + 취약 경로" },
  { value: "all", label: "전체", hint: "모든 전이 의존성" },
];

function Toolbar({ total, shown, onSearch }: { total: number; shown: number; onSearch: () => void }) {
  const { view, setView, showCode, toggleCode, showDev, toggleDev, minSeverity, setMinSeverity, search, setSearch } = useGraphStore();
  return (
    <div className="absolute top-3 left-3 flex max-w-[calc(100%-240px)] flex-wrap items-center gap-2 rounded-lg border bg-card/95 p-2 shadow-sm backdrop-blur">
      <div className="flex rounded-md bg-muted p-0.5">
        {views.map((v) => (
          <button
            key={v.value}
            type="button"
            title={v.hint}
            onClick={() => setView(v.value)}
            className={cn("rounded px-2.5 py-1 text-xs font-medium", view === v.value ? "bg-card shadow-sm" : "text-muted-foreground hover:text-foreground")}
          >
            {v.label}
          </button>
        ))}
      </div>
      <label className="flex items-center gap-1 text-xs">
        <input type="checkbox" checked={showCode} onChange={toggleCode} className="accent-primary" /> 코드
      </label>
      <label className="flex items-center gap-1 text-xs">
        <input type="checkbox" checked={showDev} onChange={toggleDev} className="accent-primary" /> dev 의존성
      </label>
      <select
        value={minSeverity}
        onChange={(e) => setMinSeverity(e.target.value as Severity)}
        className="h-7 rounded-md border bg-card px-1.5 text-xs"
        aria-label="최소 심각도"
      >
        <option value="UNKNOWN">모든 심각도</option>
        <option value="LOW">낮음 이상</option>
        <option value="MEDIUM">중간 이상</option>
        <option value="HIGH">높음 이상</option>
        <option value="CRITICAL">치명만</option>
      </select>
      <form
        className="relative"
        onSubmit={(e) => {
          e.preventDefault();
          onSearch();
        }}
      >
        <Search className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="컴포넌트 검색" className="h-7 w-40 pl-7 text-xs" />
      </form>
      <span className="text-xs text-muted-foreground tabular-nums">
        {shown} / {total} 노드
      </span>
    </div>
  );
}

function Legend() {
  return (
    <div className="absolute bottom-3 left-3 flex flex-wrap items-center gap-3 rounded-lg border bg-card/95 px-3 py-2 text-[11px] shadow-sm backdrop-blur">
      {SEVERITIES.filter((s) => s !== "UNKNOWN").map((s) => (
        <span key={s} className="flex items-center gap-1">
          <span className={cn("size-2.5 rounded-sm", severityClass[s].badge)} />
          {severityLabel[s]}
        </span>
      ))}
      <span className="flex items-center gap-1 text-muted-foreground">
        <span className="inline-block w-5 border-t border-dashed border-muted-foreground" /> import
      </span>
      <span className="text-muted-foreground">노드에 마우스를 올리면 CVE 상세와 조치 방법</span>
    </div>
  );
}

import { Background, ReactFlow, ReactFlowProvider, useReactFlow, useStore } from "@xyflow/react";
import { LoaderCircle, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ScanGraph } from "@/lib/api";
import { buildFlowGraph } from "./graph-model";
import { kindLabel, nodeTypes } from "./graph-node";
import { NodeHoverContent, ScanContext } from "./node-hover-content";
import { filterProjection, indexGraph, projectGraph, rankRisks, summarizeGroups, validSelection, type ExplorerMode, type RiskFilters } from "./explorer-model";
import { defaultFilters, ExplorerToolbar, modeLabels } from "./explorer-toolbar";
import { RiskList } from "./risk-list";
import { GraphNavigator, motionDuration, navigationPadding } from "./graph-navigator";
import { initialFitNodes } from "./graph-navigation";
import { useGraphLayout } from "./use-graph-layout";
import "./risk-explorer.css";

export function ScanGraphView({ scanName, graph }: { scanName: string; graph: ScanGraph }) {
  // Scan identity owns all ephemeral selection/expansion/viewport state.
  return <ScanContext value={scanName}><ReactFlowProvider key={scanName}><GraphExplorer key={scanName} graph={graph} /></ReactFlowProvider></ScanContext>;
}

function GraphExplorer({ graph }: { graph: ScanGraph }) {
  const [mode, setMode] = useState<ExplorerMode>("overview");
  const [filters, setFilters] = useState<RiskFilters>(defaultFilters);
  const [selectedId, setSelected] = useState<string>();
  const [detailOpen, setDetailOpen] = useState(false);
  const [expanded, setExpanded] = useState(new Set<string>());
  const [mapVisible, setMapVisible] = useState(false);
  const [listCollapsed, setListCollapsed] = useState(false);
  const [minimapPreference, setMinimapPreference] = useState<boolean>();
  const index = useMemo(() => indexGraph(graph), [graph]);
  const rows = useMemo(() => rankRisks(graph.nodes, filters), [graph.nodes, filters]);
  const rowById = useMemo(() => new Map(rows.map(row => [row.node.id, row])), [rows]);
  const active = filters.search.trim() !== "" || filters.kevOnly || filters.minSeverity !== "UNKNOWN";
  const selected = validSelection(index, rows, selectedId, filters);
  useEffect(() => { if (selectedId && !selected) { setSelected(undefined); setMode(v => v === "path" ? "overview" : v); } }, [selectedId, selected]);
  const currentMode = mode === "path" && !selected ? "overview" : mode;
  const pathSelection = currentMode === "path" ? selected : undefined;
  const base = useMemo(() => {
    const projection = projectGraph(index, currentMode, expanded, pathSelection);
    if (currentMode === "path") return projection; // Preserve prerequisite context, including dev/code intermediates.
    const nodes = projection.nodes.filter(n => (filters.showDev || !n.dev) && (filters.showCode || n.kind !== "package"));
    const ids = new Set(nodes.map(n => n.id));
    return { ...projection, nodes, edges: projection.edges.filter(e => ids.has(e.source) && ids.has(e.target)) };
  }, [index, currentMode, expanded, pathSelection, filters.showCode, filters.showDev]);
  const visible = useMemo(() => filterProjection(index, base, rows, currentMode, active), [index, base, rows, currentMode, active]);
  const visibleNodeKey = useMemo(() => JSON.stringify(visible.nodes.map(n => n.id)), [visible.nodes]);
  const summaries = useMemo(() => summarizeGroups(index, rows), [index, rows]);
  const direction = currentMode === "path" ? "DOWN" : "RIGHT";
  const placement = useGraphLayout(base, direction);
  const { fitView, getNodes } = useReactFlow();
  const canvasWidth = useStore(state => state.width);
  const canvasHeight = useStore(state => state.height);
  const minimapCollapsed = minimapPreference ?? canvasWidth < 700;
  const toggleExpanded = useCallback((id: string) => setExpanded(previous => {
    const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next;
  }), []);
  const model = useMemo(() => {
    const flow = buildFlowGraph(visible, placement.positions, filters.minSeverity);
    return {
      nodes: flow.nodes.map(n => ({ ...n, selected: selected === n.id, ariaLabel: `${n.data.node.label} ${n.data.node.version ?? ""}`, data: {
        ...n.data, severity: rowById.get(n.id)?.severity, findingCount: rowById.get(n.id)?.findings.length ?? 0,
        summary: currentMode === "overview" ? summaries.get(n.id) : undefined,
        expanded: expanded.has(n.id), childCount: index.outgoing.get(n.id)?.length ?? 0, vertical: direction === "DOWN",
        onExpand: currentMode === "overview" && n.data.node.kind !== "repository" ? toggleExpanded : undefined,
      } })),
      edges: flow.edges.map(e => ({ ...e, animated: false, style: { ...e.style, stroke: currentMode === "path" ? "var(--primary)" : undefined, opacity: currentMode === "path" ? 0.95 : 0.5, strokeWidth: currentMode === "path" ? 2 : 1 } })),
    };
  }, [visible, placement.positions, filters.minSeverity, selected, rowById, currentMode, summaries, expanded, index, toggleExpanded, direction]);

  // Filters reuse geometry; debounce only the camera fit to the remaining nodes.
  useEffect(() => {
    if (placement.loading || placement.error) return;
    let first = 0, second = 0;
    const timer = window.setTimeout(() => {
      first = requestAnimationFrame(() => { second = requestAnimationFrame(() => {
        const nodes = initialFitNodes(getNodes(), currentMode, selected, canvasWidth, canvasHeight, minimapCollapsed);
        void fitView({ nodes, padding: navigationPadding(canvasWidth, minimapCollapsed), maxZoom: 1, duration: motionDuration() });
      }); });
    }, 150);
    return () => { window.clearTimeout(timer); cancelAnimationFrame(first); cancelAnimationFrame(second); };
  }, [placement.positions, placement.loading, placement.error, fitView, getNodes, canvasWidth, canvasHeight, minimapCollapsed, currentMode, selected, visibleNodeKey]);
  const closeDetail = useCallback(() => setDetailOpen(false), []);
  const clearSelection = () => { setSelected(undefined); setDetailOpen(false); setMode("overview"); };
  useEffect(() => {
    const escape = (event: KeyboardEvent) => { if (event.key === "Escape") closeDetail(); };
    window.addEventListener("keydown", escape); return () => window.removeEventListener("keydown", escape);
  }, [closeDetail]);
  const reset = () => { setFilters(defaultFilters); clearSelection(); setExpanded(new Set()); };
  const pick = (id: string) => { setSelected(id); setDetailOpen(true); setMode("path"); };
  const detail = selected && detailOpen ? index.byId.get(selected) : undefined;
  const matching = selected ? rowById.get(selected) : undefined;

  return <section className={`risk-explorer ${mapVisible ? "map-visible" : ""} ${detail ? "has-detail" : ""}`} aria-label="의존성 위험 탐색기">
    <ExplorerToolbar mode={currentMode} setMode={setMode} filters={filters} setFilters={setFilters} onReset={reset} mapVisible={mapVisible} onToggleMap={() => { setMapVisible(v => !v); setDetailOpen(false); }} selected={selected} />
    <div className="explorer-status" aria-live="polite"><span>{modeLabels[currentMode]} · 표시 노드 {visible.nodes.length} / 전체 {graph.nodes.length}</span><span>일치하는 발견 {rows.reduce((sum, r) => sum + r.findings.length, 0)}건 · 취약 컴포넌트 {rows.length}</span></div>
    <div className="explorer-workspace">
      <RiskList rows={rows} selected={selected} onSelect={pick} onReset={reset} collapsed={listCollapsed} onToggle={() => setListCollapsed(v => !v)} />
      <div className="explorer-map">
        <div className="map-context">
          {currentMode === "overview" ? <><span>프로젝트 / 매니페스트의 + 버튼으로 한 단계씩 탐색합니다.</span>{expanded.size > 0 && <button type="button" onClick={() => setExpanded(new Set())}>모두 접기</button>}<span className="text-muted-foreground">공유 의존성은 그룹별 중복 집계됩니다.</span></> : currentMode === "path" ? <><span>선택 컴포넌트의 상위 의존 관계 · 실행 가능한 공격 경로를 뜻하지 않습니다.</span><button type="button" onClick={clearSelection}>개요로 돌아가기</button></> : currentMode === "vulnerable" ? <span>필터와 일치하는 발견이 있는 컴포넌트만 표시합니다. 정상 노드는 제외됩니다.</span> : <span>의존 구조 탐색 · 필터 적용 시 일치 컴포넌트와 상위 문맥만 표시합니다.</span>}
          {selected && !detailOpen && <button type="button" onClick={() => setDetailOpen(true)}>상세 열기</button>}
          {index.orphanComponents > 0 && <span>프로젝트 미연결: 취약 컴포넌트 {index.orphanComponents} · 발견 {index.orphanFindings}건 (목록 포함)</span>}
        </div>
        <div className="map-canvas" aria-busy={placement.loading}>
          <ReactFlow nodes={placement.loading || placement.error ? [] : model.nodes} edges={placement.loading || placement.error ? [] : model.edges} nodeTypes={nodeTypes} onNodeClick={(_, n) => {
            if (currentMode === "overview" && n.data.node.kind === "project") toggleExpanded(n.id); else pick(n.id);
          }} minZoom={0.04} maxZoom={2} nodesDraggable={false} nodesConnectable={false} edgesFocusable={false} proOptions={{ hideAttribution: true }}>
            <Background gap={24} size={1} />
            <GraphNavigator selected={selected} mode={currentMode} collapsed={minimapCollapsed} onToggle={() => setMinimapPreference(!minimapCollapsed)} />
          </ReactFlow>
          {placement.loading && <div className="map-state" role="status"><LoaderCircle className="size-5 animate-spin" />그래프 배치 중… {base.nodes.length}개 노드</div>}
          {placement.error && <div className="map-state" role="alert"><p>그래프 배치 실패: {placement.error}</p><button type="button" onClick={placement.retry}>다시 시도</button><button type="button" onClick={reset}>개요로 초기화</button></div>}
          {!placement.loading && !placement.error && !visible.nodes.length && <div className="map-state" role="status"><p>{graph.nodes.length ? "현재 보기에 표시할 노드가 없습니다." : "분석된 그래프가 비어 있습니다."}</p><button type="button" onClick={reset}>필터와 보기 초기화</button></div>}
        </div>
      </div>
      {detail && <aside className="explorer-detail" aria-label="선택 컴포넌트 상세">
        <div className="detail-heading"><strong>컴포넌트 상세</strong><button type="button" autoFocus aria-label="컴포넌트 상세 닫기" onClick={closeDetail}><X size={18} /></button></div>
        <p className="text-muted-foreground">일치 {matching?.findings.length ?? 0}건 / 전체 발견 {detail.findings?.length ?? 0}건</p>
        <NodeHoverContent key={detail.id} node={matching ? { ...detail, findings: matching.findings } : detail} kindLabel={kindLabel[detail.kind]} />
        <details className="component-identity"><summary>컴포넌트 ID</summary><code>{detail.id}</code></details>
      </aside>}
    </div>
  </section>;
}

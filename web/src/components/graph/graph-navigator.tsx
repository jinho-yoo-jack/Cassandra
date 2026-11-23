import { MiniMap, Panel, useReactFlow, useViewport, useStore } from "@xyflow/react";

import { severityClass } from "@/lib/utils";
import type { FlowNode } from "./graph-model";
import { modeLabels } from "./explorer-toolbar";
import type { ExplorerMode } from "./explorer-model";
import { navigationPadding } from "./graph-navigation";
export { navigationPadding } from "./graph-navigation";

export const motionDuration = () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 200;

export function GraphNavigator({ selected, mode, collapsed, onToggle }: { selected?: string; mode: ExplorerMode; collapsed: boolean; onToggle: () => void }) {
  const width = useStore(state => state.width);
  const { zoom } = useViewport();
  const { fitView, zoomIn, zoomOut, setCenter } = useReactFlow();
  return <Panel position="bottom-right" className="graph-navigator">
    <div className="navigator-heading"><span>현재 보기 · {modeLabels[mode]}</span><button type="button" aria-expanded={!collapsed} aria-label={collapsed ? "미니맵 펼치기" : "미니맵 접기"} onClick={onToggle}>{collapsed ? "펼치기" : "접기"}</button></div>
    {!collapsed && <MiniMap<FlowNode> className="explorer-minimap" position="bottom-right" pannable zoomable onClick={(_, point) => { void setCenter(point.x, point.y, { zoom, duration: motionDuration() }); }} ariaLabel="현재 필터와 보기의 지도. 밝은 테두리가 현재 화면입니다." nodeColor={n => n.data.severity ? severityClass[n.data.severity].stroke : "var(--muted-foreground)"} bgColor="var(--canvas)" maskColor="color-mix(in oklch, var(--background) 75%, transparent)" maskStrokeColor="var(--foreground)" maskStrokeWidth={3} />}
    <div className="navigator-controls"><button type="button" aria-label="축소" onClick={() => zoomOut({ duration: motionDuration() })}>−</button><output aria-label="현재 확대 비율">{Math.round(zoom * 100)}%</output><button type="button" aria-label="확대" onClick={() => zoomIn({ duration: motionDuration() })}>+</button><button type="button" onClick={() => fitView({ padding: navigationPadding(width, collapsed), maxZoom: 1, duration: motionDuration() })}>전체 맞춤</button><button type="button" disabled={!selected} onClick={() => selected && fitView({ nodes: [{ id: selected }], padding: navigationPadding(width, collapsed), maxZoom: 1.4, duration: motionDuration() })}>선택 맞춤</button></div>
  </Panel>;
}

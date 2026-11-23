import type { Severity } from "@/lib/api-types";
import type { ExplorerMode, RiskFilters } from "./explorer-model";

export const modeLabels: Record<ExplorerMode, string> = { overview: "프로젝트 개요", vulnerable: "취약 컴포넌트만", direct: "직접 의존성", all: "전체 구조", path: "선택 의존 경로" };
export const defaultFilters: RiskFilters = { minSeverity: "UNKNOWN", kevOnly: false, search: "", showCode: true, showDev: true };
export function ExplorerToolbar({ mode, setMode, filters, setFilters, onReset, mapVisible, onToggleMap, selected }: {
  mode: ExplorerMode; setMode: (mode: ExplorerMode) => void; filters: RiskFilters; setFilters: (filters: RiskFilters) => void;
  onReset: () => void; mapVisible: boolean; onToggleMap: () => void; selected?: string;
}) {
  return <header className="explorer-toolbar">
    <div className="explorer-modes" aria-label="그래프 보기">
      {Object.entries(modeLabels).map(([value, label]) => <button key={value} type="button" aria-pressed={value === mode} disabled={value === "path" && !selected} onClick={() => setMode(value as ExplorerMode)}>{label}</button>)}
    </div>
    <div className="explorer-filters">
      <label className="explorer-search"><span className="sr-only">컴포넌트 또는 취약점 검색</span><input type="search" value={filters.search} placeholder="컴포넌트 · 버전 · CVE 검색" onChange={e => setFilters({ ...filters, search: e.target.value })} /></label>
      <select aria-label="최소 심각도" value={filters.minSeverity} onChange={e => setFilters({ ...filters, minSeverity: e.target.value as Severity })}>
        <option value="UNKNOWN">모든 심각도</option><option value="LOW">낮음 이상</option><option value="MEDIUM">중간 이상</option><option value="HIGH">높음 이상</option><option value="CRITICAL">치명만</option>
      </select>
      <label><input type="checkbox" checked={filters.kevOnly} onChange={e => setFilters({ ...filters, kevOnly: e.target.checked })} /> KEV만</label>
      <label><input type="checkbox" checked={filters.showDev} onChange={e => setFilters({ ...filters, showDev: e.target.checked })} /> dev 포함</label>
      <label><input type="checkbox" checked={filters.showCode} onChange={e => setFilters({ ...filters, showCode: e.target.checked })} /> 코드 포함</label>
      <button type="button" onClick={onReset}>초기화</button>
      <button type="button" className="mobile-map-toggle" aria-expanded={mapVisible} onClick={onToggleMap}>{mapVisible ? "목록 보기" : "지도 보기"}</button>
    </div>
  </header>;
}

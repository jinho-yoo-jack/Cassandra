import { ChevronDown, ChevronUp } from "lucide-react";
import type { RiskRow } from "./explorer-model";
import { percent, severityLabel } from "@/lib/utils";

export function RiskList({ rows, selected, onSelect, onReset, collapsed, onToggle }: {
  rows: RiskRow[]; selected?: string; onSelect: (id: string) => void; onReset: () => void; collapsed: boolean; onToggle: () => void;
}) {
  const findings = rows.reduce((sum, row) => sum + row.findings.length, 0);
  return <aside className={`risk-list ${collapsed ? "is-collapsed" : ""}`} aria-label="위험 우선순위">
    <button type="button" className="risk-list-heading" aria-expanded={!collapsed} onClick={onToggle}>
      <span><strong>위험 우선순위</strong><span className="block text-muted-foreground tabular-nums">취약 컴포넌트 {rows.length} · 발견 {findings}건</span></span>
      {collapsed ? <ChevronDown size={18} /> : <ChevronUp size={18} />}
    </button>
    {!collapsed && <>
      <p className="risk-order">KEV → 심각도 → EPSS → 패치<br />활성 필터와 일치하는 발견만 비교합니다.</p>
      <div className="risk-list-scroll">
        {rows.length === 0 ? <div className="explorer-empty" role="status"><p>일치하는 취약점이 없습니다.</p><button type="button" onClick={onReset}>필터 초기화</button></div> :
          <ol>{rows.map((row, i) => <li key={row.node.id}>
            <button type="button" className="risk-row" aria-pressed={selected === row.node.id} onClick={() => onSelect(row.node.id)} title={`${row.node.label} @${row.node.version ?? "버전 미상"} · ${row.node.id}`}>
              <span className="risk-row-title"><span className="text-muted-foreground tabular-nums">{i + 1}</span><strong>{row.node.label}</strong><span className="risk-severity" data-severity={row.severity}>{severityLabel[row.severity]}</span></span>
              <span className="block truncate font-mono text-muted-foreground">{row.node.version ?? "버전 미상"} · 발견 {row.findings.length}건</span>
              <span className="risk-reasons">{row.kev && <span>KEV 등록</span>}<span>EPSS {row.epss === undefined ? "미상" : percent(row.epss)}</span><span>{row.fixable ? "패치 있음" : "패치 미제공"}</span></span>
            </button>
          </li>)}</ol>}
      </div>
    </>}
  </aside>;
}

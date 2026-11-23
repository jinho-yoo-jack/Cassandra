import { Handle, type NodeProps, Position, useStore } from "@xyflow/react";
import { Boxes, Container, FolderTree, GitBranch, Package, Server } from "lucide-react";
import { memo } from "react";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import type { NodeKind } from "@/lib/api";
import { cn, severityLabel } from "@/lib/utils";
import type { FlowNode } from "./graph-model";
import { NodeHoverContent } from "./node-hover-content";

export type { FlowNode, FlowNodeData } from "./graph-model";
const kindIcon = { repository: GitBranch, project: FolderTree, package: Boxes, library: Package, image: Container, process: Server };
export const kindLabel: Record<NodeKind, string> = { repository: "저장소", project: "프로젝트", package: "코드", library: "라이브러리", image: "이미지", process: "프로세스" };
function GraphNodeCard({ data, selected }: NodeProps<FlowNode>) {
  const { node, severity, findingCount, summary } = data;
  const glyphCount = summary?.vulnerableComponents ?? findingCount;
  const level = useStore(state => state.transform[2] < 0.35 ? "far" : state.transform[2] < 0.75 ? "medium" : "near");
  const Icon = kindIcon[node.kind];
  const label = `${node.label} ${node.version ?? ""}, ${summary ? `멤버 ${summary.members}, 취약 컴포넌트 ${summary.vulnerableComponents}` : `발견 ${findingCount}건`}`;
  const card = <div className={cn("explorer-node", `zoom-${level}`, data.dimmed && "is-dimmed", (selected || data.highlighted) && "is-selected")} data-severity={severity} title={label} aria-label={label}>
    <Icon className="node-icon" aria-hidden />
    {level === "far" ? <div className="node-glyph" aria-hidden><span />{(summary || glyphCount > 0) && <b>{glyphCount}</b>}</div> : <div className="node-copy">
      <strong title={node.label}>{node.label}</strong>
      {summary ? <><span className="node-subtitle" title={node.path}>{node.path ?? kindLabel[node.kind]}</span><span className="node-counts">멤버 {summary.members} · 취약 {summary.vulnerableComponents}</span></> : <>
        {level === "near" && <span className="node-subtitle" title={node.version}>{node.version ?? (node.kind === "process" ? "버전 미상" : kindLabel[node.kind])} {node.dev ? "· dev" : ""}</span>}
        {severity && <span className="node-counts">{severityLabel[severity]} · 발견 {findingCount}건</span>}
      </>}
    </div>}
    {!!data.childCount && data.onExpand && level !== "far" && <button type="button" className="node-expand nodrag nopan" aria-expanded={data.expanded} aria-label={`${node.label} ${data.expanded ? "접기" : "하위 의존성 펼치기"}`} onClick={e => { e.stopPropagation(); data.onExpand?.(node.id); }}>{data.expanded ? "−" : "+"}</button>}
  </div>;
  return <>
    <Handle type="target" position={data.vertical ? Position.Top : Position.Left} className="!size-1.5 !border-0 !bg-muted-foreground/40" />
    <HoverCard openDelay={600} closeDelay={150}>
      <HoverCardTrigger asChild>{card}</HoverCardTrigger>
      <HoverCardContent side="right" align="start" className="w-[min(440px,calc(100vw-24px))]"><NodeHoverContent node={node} kindLabel={kindLabel[node.kind]} /></HoverCardContent>
    </HoverCard>
    <Handle type="source" position={data.vertical ? Position.Bottom : Position.Right} className="!size-1.5 !border-0 !bg-muted-foreground/40" />
  </>;
}
export const nodeTypes = { vg: memo(GraphNodeCard) };

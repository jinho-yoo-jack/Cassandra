import { Handle, type Node, type NodeProps, Position } from "@xyflow/react";
import { Boxes, Container, Flame, FolderTree, GitBranch, Package, Server } from "lucide-react";
import { memo } from "react";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import type { GraphNode, NodeKind, Severity } from "@/lib/api";
import { cn, severityClass } from "@/lib/utils";
import { NodeHoverContent } from "./node-hover-content";

export type FlowNodeData = {
  node: GraphNode;
  severity?: Severity;
  findingCount: number;
  dimmed: boolean;
  highlighted: boolean;
};
export type FlowNode = Node<FlowNodeData, "vg">;

const kindIcon: Record<NodeKind, typeof Package> = {
  repository: GitBranch,
  project: FolderTree,
  package: Boxes,
  library: Package,
  image: Container,
  process: Server,
};

const kindLabel: Record<NodeKind, string> = {
  repository: "저장소",
  project: "프로젝트",
  package: "코드",
  library: "라이브러리",
  image: "이미지",
  process: "프로세스",
};

function subtitle(n: GraphNode): string {
  switch (n.kind) {
    case "project":
      return `${n.ecosystem ?? ""} · ${n.path ?? ""}`;
    case "package":
      return `${n.language ?? ""} 패키지`;
    case "process":
      return n.version ? `v${n.version}` : "미고정 태그 — 버전 확인 불가";
    case "repository":
      return n.version ? `@${n.version}` : "";
    default:
      return [n.version, n.ecosystem, n.direct ? "직접" : "전이", n.dev ? "dev" : ""].filter(Boolean).join(" · ");
  }
}

function GraphNodeCard({ data, selected }: NodeProps<FlowNode>) {
  const { node, severity, findingCount, dimmed, highlighted } = data;
  const Icon = kindIcon[node.kind];
  const kev = node.findings?.some((f) => f.knownExploited);
  const unpinned = node.kind === "process" && !node.version;

  const card = (
    <div
      className={cn(
        "group flex h-[58px] w-[236px] items-center gap-2.5 rounded-lg border-2 bg-card px-2.5 shadow-sm transition-[opacity,box-shadow]",
        severity ? severityClass[severity].border : "border-border",
        node.kind === "repository" && "border-primary bg-primary/5",
        unpinned && "border-dashed border-sev-medium",
        dimmed && "opacity-25",
        (selected || highlighted) && "ring-4 ring-primary/40",
      )}
    >
      <div
        className={cn(
          "flex size-8 shrink-0 items-center justify-center rounded-md",
          severity ? cn(severityClass[severity].badge) : "bg-muted text-muted-foreground",
        )}
      >
        <Icon className="size-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1">
          <span className="truncate text-[13px] font-semibold leading-tight" title={node.label}>
            {node.label}
          </span>
          {kev && <Flame className="size-3.5 shrink-0 text-sev-critical" aria-label="CISA KEV" />}
        </div>
        <div className="truncate text-[11px] text-muted-foreground">{subtitle(node) || kindLabel[node.kind]}</div>
      </div>
      {severity && findingCount > 0 && <SeverityBadge severity={severity} count={findingCount} />}
    </div>
  );

  return (
    <>
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-muted-foreground/40" />
      <HoverCard openDelay={250} closeDelay={150}>
        <HoverCardTrigger asChild>{card}</HoverCardTrigger>
        <HoverCardContent side="right" align="start" className={cn(findingCount > 0 ? "w-[440px]" : "w-80")}>
          <NodeHoverContent node={node} kindLabel={kindLabel[node.kind]} />
        </HoverCardContent>
      </HoverCard>
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-muted-foreground/40" />
    </>
  );
}

export const nodeTypes = { vg: memo(GraphNodeCard) };

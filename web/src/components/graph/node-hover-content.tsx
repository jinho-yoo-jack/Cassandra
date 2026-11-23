import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ChevronDown, ChevronRight, ExternalLink, Flame, LoaderCircle, Wrench } from "lucide-react";
import { createContext, useContext, useState } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { ApiError, api, type GraphNode, type NodeFinding } from "@/lib/api";
import { advisoryURL, percent, severityRank } from "@/lib/utils";

/** ScanContext gives graph nodes the scan they belong to. */
export const ScanContext = createContext<string>("");

const VISIBLE_FINDINGS = 4;

export function NodeHoverContent({ node, kindLabel }: { node: GraphNode; kindLabel: string }) {
  const [showAll, setShowAll] = useState(false);
  const findings = [...(node.findings ?? [])].sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || (b.score ?? 0) - (a.score ?? 0));
  const shown = showAll ? findings : findings.slice(0, VISIBLE_FINDINGS);

  return (
    <div className="space-y-3">
      <div>
        <div className="text-xs text-muted-foreground">{kindLabel}</div>
        <div className="font-semibold break-all">
          {node.label}
          {node.version && <span className="ml-1 font-normal text-muted-foreground">@{node.version}</span>}
        </div>
        {node.purl && <div className="mt-0.5 font-mono text-[11px] break-all text-muted-foreground">{node.purl}</div>}
        {node.path && node.kind !== "package" && <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">{node.path}</div>}
        {node.kind === "process" && !node.version && (
          <p className="mt-2 rounded-md bg-sev-medium/15 p-2 text-xs">
            이미지 태그가 버전을 고정하지 않아(예: <code>latest</code>, <code>5</code>) 실제 실행 버전을 알 수 없습니다. 정확한 버전 태그로 고정해야 CVE를 판정할 수 있습니다.
          </p>
        )}
      </div>

      {findings.length === 0 ? (
        node.kind === "library" || node.kind === "process" ? (
          <p className="text-sm text-muted-foreground">알려진 취약점이 없습니다.</p>
        ) : null
      ) : (
        <div className="max-h-[60vh] space-y-2 overflow-y-auto pr-1">
          <div className="text-xs font-medium text-muted-foreground">취약점 {findings.length}건</div>
          {shown.map((f) => (
            <FindingItem key={f.vulnerabilityID} node={node} finding={f} />
          ))}
          {findings.length > VISIBLE_FINDINGS && (
            <Button variant="ghost" size="sm" className="w-full" onClick={() => setShowAll((v) => !v)}>
              {showAll ? "접기" : `${findings.length - VISIBLE_FINDINGS}건 더 보기`}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

function FindingItem({ node, finding }: { node: GraphNode; finding: NodeFinding }) {
  const [expanded, setExpanded] = useState(false);
  const scanName = useContext(ScanContext);
  const navigate = useNavigate();

  const details = useQuery({
    queryKey: ["vulnerabilities", finding.vulnerabilityID],
    queryFn: () => api.getVulnerability(finding.vulnerabilityID),
    enabled: expanded,
    staleTime: 60 * 60 * 1000,
  });

  const remediate = useMutation({
    mutationFn: () => api.createRemediation({ scanName, vulnerabilityID: finding.vulnerabilityID, componentID: node.id }),
    onSuccess: (r) => {
      toast.success(`${finding.displayID} 조치를 시작했습니다`);
      navigate({ to: "/remediations/$name", params: { name: r.metadata.name } });
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status.reason === "AlreadyExists" && err.status.details?.name) {
        toast.info("이미 진행 중인 조치가 있어 해당 화면으로 이동합니다");
        navigate({ to: "/remediations/$name", params: { name: err.status.details.name } });
        return;
      }
      toast.error(err.message);
    },
  });

  return (
    <div className="rounded-md border bg-background/60 p-2.5">
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          <a href={advisoryURL(finding.displayID)} target="_blank" rel="noreferrer" className="font-mono text-sm font-semibold hover:underline">
            {finding.displayID}
          </a>
          {finding.knownExploited && (
            <span className="inline-flex items-center gap-0.5 rounded bg-sev-critical/15 px-1 text-[11px] font-semibold text-sev-critical">
              <Flame className="size-3" /> KEV
            </span>
          )}
        </div>
        <div className="shrink-0 text-right text-[11px] text-muted-foreground tabular-nums">
          {finding.score ? <div>CVSS {finding.score.toFixed(1)}</div> : null}
          {finding.epss !== undefined && <div>EPSS {percent(finding.epss)}</div>}
        </div>
      </div>
      {finding.summary && <p className="mt-1.5 text-[13px] leading-snug">{finding.summary}</p>}

      <div className="mt-2 rounded bg-muted/70 p-2 text-xs leading-relaxed whitespace-pre-line">
        <div className="mb-0.5 font-semibold">조치 방법</div>
        {finding.remediation || "조치 정보가 없습니다."}
      </div>

      <div className="mt-2 flex items-center justify-between gap-2">
        <button type="button" className="inline-flex items-center gap-0.5 text-xs text-muted-foreground hover:text-foreground" onClick={() => setExpanded((v) => !v)}>
          {expanded ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
          상세 정보
        </button>
        <Button
          size="sm"
          disabled={!finding.fixedVersion || remediate.isPending}
          onClick={() => remediate.mutate()}
          title={
            !finding.fixedVersion
              ? "패치 버전이 없습니다"
              : node.fixTarget && node.fixTarget !== finding.fixedVersion
                ? `이 취약점은 ${finding.fixedVersion}에서 수정되지만, 이 컴포넌트의 다른 취약점까지 함께 해결하도록 ${node.fixTarget}로 올립니다`
                : `${finding.fixedVersion}로 조치`
          }
        >
          {remediate.isPending ? <LoaderCircle className="animate-spin" /> : <Wrench />}
          {finding.fixedVersion ? `조치 → ${node.fixTarget ?? finding.fixedVersion}` : "패치 없음"}
        </Button>
      </div>

      {expanded && (
        <div className="mt-2 space-y-2 border-t pt-2 text-xs">
          {details.isPending && <LoaderCircle className="size-4 animate-spin text-muted-foreground" />}
          {details.error && <p className="text-destructive">{details.error.message}</p>}
          {details.data && (
            <>
              {details.data.details && (
                <div className="markdown max-h-48 overflow-y-auto text-xs text-muted-foreground [&_h3]:mt-2 [&_h3]:text-xs">
                  <Markdown remarkPlugins={[remarkGfm]}>{details.data.details}</Markdown>
                </div>
              )}
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                {details.data.cvss?.vector && (
                  <>
                    <dt className="text-muted-foreground">CVSS</dt>
                    <dd className="font-mono break-all">{details.data.cvss.vector}</dd>
                  </>
                )}
                {details.data.cwes && details.data.cwes.length > 0 && (
                  <>
                    <dt className="text-muted-foreground">CWE</dt>
                    <dd>{details.data.cwes.join(", ")}</dd>
                  </>
                )}
                {details.data.kev && (
                  <>
                    <dt className="text-muted-foreground">KEV 기한</dt>
                    <dd>
                      {details.data.kev.dueDate} — {details.data.kev.requiredAction}
                    </dd>
                  </>
                )}
                {details.data.aliases && details.data.aliases.length > 0 && (
                  <>
                    <dt className="text-muted-foreground">별칭</dt>
                    <dd className="break-all">{details.data.aliases.join(", ")}</dd>
                  </>
                )}
              </dl>
              {details.data.references && details.data.references.length > 0 && (
                <ul className="space-y-0.5">
                  {details.data.references.slice(0, 6).map((r) => (
                    <li key={r.url} className="truncate">
                      <a href={r.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                        <ExternalLink className="size-3 shrink-0" />
                        {r.type && <span className="text-muted-foreground">[{r.type}]</span>}
                        <span className="truncate">{r.url}</span>
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

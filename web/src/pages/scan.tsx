import { useQuery } from "@tanstack/react-query";
import { BellRing, Download, Flame, LoaderCircle } from "lucide-react";
import { ScanGraphView } from "@/components/graph/scan-graph";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useWatch } from "@/hooks/use-watch";
import { api, type Scan } from "@/lib/api";
import { SEVERITIES, timeAgo } from "@/lib/utils";

export function ScanPage({ name }: { name: string }) {
  const scan = useQuery({ queryKey: ["scans", name], queryFn: () => api.getScan(name) });
  useWatch<Scan>("scans", { name });
  const phase = scan.data?.status.phase;
  const evaluated = scan.data?.status.lastEvaluatedTime;
  const graph = useQuery({
    // Re-evaluation by a feed update changes the graph: key on its time.
    queryKey: ["graph", name, evaluated],
    queryFn: () => api.getGraph(name),
    enabled: phase === "Succeeded",
    placeholderData: (prev) => prev,
  });

  if (scan.error) return <p className="p-6 text-destructive">{scan.error.message}</p>;
  if (!scan.data) return <LoaderCircle className="m-6 size-5 animate-spin" />;
  const s = scan.data;
  const newFindings = s.status.conditions?.find((c) => c.type === "NewFindings" && c.status === "True");

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b bg-card px-4 py-3 sm:px-6">
        <div className="min-w-0">
          <a href={s.status.repository?.url ?? s.spec.repositoryURL} target="_blank" rel="noreferrer" className="font-semibold hover:underline">
            {s.spec.repositoryURL.replace("https://github.com/", "")}
          </a>
          <div className="text-xs text-muted-foreground">
            {s.status.repository?.branch && <span className="font-mono">{s.status.repository.branch}</span>}
            {s.status.repository?.commit && <span className="font-mono"> @ {s.status.repository.commit.slice(0, 12)}</span>}
            {evaluated && <> · 마지막 평가 {timeAgo(evaluated)}</>}
          </div>
        </div>
        {s.status.summary && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-sm text-muted-foreground">
              컴포넌트 {s.status.summary.components} · 취약 {s.status.summary.vulnerableComponents}
            </span>
            {SEVERITIES.map((sev) => {
              const n = s.status.summary?.bySeverity?.[sev];
              return n ? <SeverityBadge key={sev} severity={sev} count={n} /> : null;
            })}
            {s.status.summary.knownExploited > 0 && (
              <Badge variant="destructive">
                <Flame /> KEV {s.status.summary.knownExploited}
              </Badge>
            )}
          </div>
        )}
        {phase === "Succeeded" && (
          <div className="ml-auto flex gap-2">
            <Button variant="outline" size="sm" asChild>
              <a href={api.sbomURL(name, "cyclonedx")} download>
                <Download /> SBOM CycloneDX
              </a>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a href={api.sbomURL(name, "spdx")} download>
                <Download /> SBOM SPDX
              </a>
            </Button>
          </div>
        )}
      </div>
      {newFindings && (
        <div className="flex items-center gap-2 border-b bg-sev-high/10 px-6 py-2 text-sm">
          <BellRing className="size-4 text-sev-high" />
          피드 업데이트로 새 취약점이 발견되었습니다: {newFindings.message?.replace("New: ", "")} ({timeAgo(newFindings.lastTransitionTime)})
        </div>
      )}

      <div className="min-h-0 flex-1">
        {phase === "Failed" && <p className="p-6 text-destructive">스캔 실패: {s.status.message}</p>}
        {(phase === "Pending" || phase === "Running") && (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-muted-foreground">
            <LoaderCircle className="size-8 animate-spin text-primary" />
            <div>{s.status.message ?? "분석 대기 중"}</div>
          </div>
        )}
        {phase === "Succeeded" && graph.data && <ScanGraphView scanName={name} graph={graph.data} />}
        {phase === "Succeeded" && graph.isPending && <LoaderCircle className="m-6 size-5 animate-spin" />}
        {graph.error && <p className="p-6 text-destructive">{graph.error.message}</p>}
      </div>
    </div>
  );
}

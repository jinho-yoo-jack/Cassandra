import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { CircleCheck, CircleX, Flame, LoaderCircle, Radar, Rss, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { z } from "zod";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useWatch } from "@/hooks/use-watch";
import { api, type Feed, type Scan } from "@/lib/api";
import { SEVERITIES, timeAgo } from "@/lib/utils";

const repoSchema = z
  .string()
  .trim()
  .regex(/^(https:\/\/)?(www\.)?github\.com\/[\w.-]+\/[\w.-]+(\/tree\/.+)?\/?$|^[\w.-]+\/[\w.-]+$/, "GitHub 저장소 주소를 입력하세요 (예: https://github.com/owner/repo)");

export function HomePage() {
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-8 sm:px-6">
      <ScanForm />
      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        <ScanList />
        <FeedStatus />
      </div>
    </div>
  );
}

function ScanForm() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const create = useMutation({
    mutationFn: (repo: string) => api.createScan(repo),
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      navigate({ to: "/scans/$name", params: { name: scan.metadata.name } });
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Card className="gap-3">
      <CardHeader>
        <CardTitle className="text-xl">GitHub 저장소 취약점 분석</CardTitle>
        <CardDescription>
          코드와 사용 중인 라이브러리·컨테이너 이미지를 SBOM으로 추출하고, OSV·NVD·CISA KEV·EPSS로 취약점을 매칭해 그래프로 보여줍니다. 새 취약점이 공개되면 자동으로 다시 평가합니다.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-2 sm:flex-row"
          onSubmit={(e) => {
            e.preventDefault();
            const parsed = repoSchema.safeParse(url);
            if (!parsed.success) {
              setError(parsed.error.issues[0]?.message);
              return;
            }
            setError(undefined);
            const repo = parsed.data.includes("github.com") ? parsed.data : `https://github.com/${parsed.data}`;
            create.mutate(repo.startsWith("http") ? repo : `https://${repo}`);
          }}
        >
          <Input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://github.com/owner/repository"
            aria-invalid={error !== undefined}
            className="h-10 font-mono"
            autoFocus
          />
          <Button type="submit" size="lg" disabled={create.isPending}>
            {create.isPending ? <LoaderCircle className="animate-spin" /> : <Radar />}
            분석 시작
          </Button>
        </form>
        {error && <p className="mt-1.5 text-sm text-destructive">{error}</p>}
      </CardContent>
    </Card>
  );
}

function ScanList() {
  const qc = useQueryClient();
  const scans = useQuery({ queryKey: ["scans"], queryFn: api.listScans });
  useWatch<Scan>("scans", {
    onEvent: (e, prev) => {
      const before = prev?.status.summary?.vulnerabilities ?? 0;
      const after = e.object.status.summary?.vulnerabilities ?? 0;
      if (prev?.status.phase === "Succeeded" && e.object.status.phase === "Succeeded" && after > before) {
        toast.warning(`${e.object.metadata.name}: 새 취약점 ${after - before}건이 발견되었습니다`);
      }
    },
  });
  const remove = useMutation({
    mutationFn: api.deleteScan,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
    onError: (err) => toast.error(err.message),
  });
  const items = [...(scans.data?.items ?? [])].sort((a, b) => (b.metadata.creationTimestamp ?? "").localeCompare(a.metadata.creationTimestamp ?? ""));

  return (
    <Card className="gap-0 py-0">
      <CardHeader className="border-b py-4">
        <CardTitle>스캔 목록</CardTitle>
      </CardHeader>
      {scans.isPending && <LoaderCircle className="m-6 size-5 animate-spin text-muted-foreground" />}
      {scans.error && <p className="p-5 text-sm text-destructive">{scans.error.message}</p>}
      {scans.data && items.length === 0 && <p className="p-5 text-sm text-muted-foreground">아직 스캔이 없습니다. 위에 저장소 주소를 입력하세요.</p>}
      <ul className="divide-y">
        {items.map((s) => (
          <li key={s.metadata.name} className="flex items-center gap-4 px-5 py-3 hover:bg-muted/40">
            <PhaseIcon phase={s.status.phase} />
            <Link to="/scans/$name" params={{ name: s.metadata.name }} className="min-w-0 flex-1">
              <div className="truncate font-medium">{s.spec.repositoryURL.replace("https://github.com/", "")}</div>
              <div className="truncate text-xs text-muted-foreground">
                {s.status.phase === "Succeeded" ? s.status.message : (s.status.message ?? s.status.phase)} · {timeAgo(s.metadata.creationTimestamp)}
              </div>
            </Link>
            <div className="hidden flex-wrap justify-end gap-1 sm:flex">
              {s.status.summary &&
                SEVERITIES.map((sev) => {
                  const n = s.status.summary?.bySeverity?.[sev];
                  return n ? <SeverityBadge key={sev} severity={sev} count={n} /> : null;
                })}
              {s.status.summary?.knownExploited ? (
                <Badge variant="destructive">
                  <Flame /> KEV {s.status.summary.knownExploited}
                </Badge>
              ) : null}
            </div>
            <Button variant="ghost" size="icon" aria-label="삭제" onClick={() => remove.mutate(s.metadata.name)}>
              <Trash2 className="text-muted-foreground" />
            </Button>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function PhaseIcon({ phase }: { phase?: Scan["status"]["phase"] }) {
  switch (phase) {
    case "Succeeded":
      return <CircleCheck className="size-5 shrink-0 text-emerald-500" />;
    case "Failed":
      return <CircleX className="size-5 shrink-0 text-destructive" />;
    default:
      return <LoaderCircle className="size-5 shrink-0 animate-spin text-primary" />;
  }
}

const feedLabel: Record<string, string> = {
  osv: "OSV.dev",
  nvd: "NVD",
  "cisa-kev": "CISA KEV",
  "github-advisories": "GitHub Advisory 웹훅",
};

function FeedStatus() {
  const feeds = useQuery({ queryKey: ["feeds"], queryFn: api.listFeeds });
  useWatch<Feed>("feeds");
  return (
    <Card className="gap-3 self-start">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Rss className="size-4" /> 취약점 피드
        </CardTitle>
        <CardDescription>새 취약점이 들어오면 저장된 스캔을 자동으로 다시 평가합니다.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {feeds.data?.items.length === 0 && <p className="text-sm text-muted-foreground">피드가 비활성화되어 있습니다.</p>}
        {feeds.data?.items.map((f) => (
          <div key={f.metadata.name} className="text-sm">
            <div className="flex items-center justify-between">
              <span className="font-medium">{feedLabel[f.metadata.name] ?? f.metadata.name}</span>
              <Badge variant={f.status.lastError ? "destructive" : "secondary"}>{f.status.mode === "push" ? "push" : f.status.interval}</Badge>
            </div>
            <div className="text-xs text-muted-foreground">
              {f.status.lastSyncTime ? `동기화 ${timeAgo(f.status.lastSyncTime)}` : "대기 중"} · 처리 {f.status.processed} · 재평가 {f.status.matched}
            </div>
            {f.status.lastError && <div className="truncate text-xs text-destructive" title={f.status.lastError}>{f.status.lastError}</div>}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

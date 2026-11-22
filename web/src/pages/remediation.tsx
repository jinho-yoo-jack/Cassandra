import { useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  CircleCheck,
  CircleDashed,
  CircleSlash,
  CircleX,
  ExternalLink,
  FileText,
  GitPullRequest,
  Hourglass,
  LoaderCircle,
  ShieldCheck,
  TestTubeDiagonal,
  ThumbsDown,
  ThumbsUp,
} from "lucide-react";
import { useState } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Textarea } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useWatch } from "@/hooks/use-watch";
import { api, type Remediation, type RemediationPhase, type RemediationStep, type StepState } from "@/lib/api";
import { cn, timeAgo } from "@/lib/utils";

const stepLabel: Record<string, string> = {
  CreateBranch: "Feature 브랜치 생성",
  ApplyFix: "작업 진행 (버전 수정)",
  WriteTestScenarios: "테스트 시나리오 작성",
  BuildImage: "이미지 생성",
  Test: "테스트",
  Review: "검토",
  Deploy: "배포",
  PullRequest: "PR 생성",
};

export const phaseLabel: Record<RemediationPhase, string> = {
  Pending: "대기",
  Running: "진행 중",
  AwaitingReview: "검토 대기",
  Approved: "승인됨",
  Completed: "완료",
  Denied: "반려",
  Failed: "실패",
};

export function PhaseBadge({ phase }: { phase?: RemediationPhase }) {
  const variant = phase === "Failed" || phase === "Denied" ? "destructive" : phase === "Completed" ? "default" : "secondary";
  return <Badge variant={variant}>{phase ? phaseLabel[phase] : "-"}</Badge>;
}

export function RemediationPage({ name }: { name: string }) {
  const rem = useQuery({ queryKey: ["remediations", name], queryFn: () => api.getRemediation(name) });
  useWatch<Remediation>("remediations", { name });

  if (rem.error) return <p className="p-6 text-destructive">{rem.error.message}</p>;
  if (!rem.data) return <LoaderCircle className="m-6 size-5 animate-spin" />;
  const r = rem.data;
  const st = r.status;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-5 px-4 py-6 sm:px-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-mono text-2xl font-semibold">{st.docsID}</h1>
            <PhaseBadge phase={st.phase} />
            {st.kind === "Image" && <Badge variant="outline">컨테이너 이미지</Badge>}
          </div>
          <p className="mt-1 text-muted-foreground">
            <span className="font-medium text-foreground">{st.component?.name}</span> {st.fromVersion} → <span className="font-semibold text-foreground">{st.toVersion ?? "…"}</span>
            {st.branch && (
              <>
                {" "}
                · <span className="font-mono text-xs">{st.branch}</span>
              </>
            )}
          </p>
          <p className="text-sm text-muted-foreground">
            스캔{" "}
            <Link to="/scans/$name" params={{ name: r.spec.scanName }} className="text-primary hover:underline">
              {r.spec.scanName}
            </Link>{" "}
            · {st.message}
          </p>
        </div>
        {st.pullRequestURL && (
          <Button asChild>
            <a href={st.pullRequestURL} target="_blank" rel="noreferrer">
              <GitPullRequest /> Pull Request 열기
            </a>
          </Button>
        )}
      </div>

      <Pipeline steps={st.steps ?? []} />

      {st.phase === "AwaitingReview" && <ReviewPanel remediation={r} />}
      {st.reviewer && (
        <p className="text-sm text-muted-foreground">
          검토자 <span className="font-medium text-foreground">{st.reviewer}</span>
          {st.reviewComment && <> — “{st.reviewComment}”</>}
        </p>
      )}

      <Tabs defaultValue="tests">
        <TabsList>
          <TabsTrigger value="tests">
            <TestTubeDiagonal /> 테스트 결과
          </TabsTrigger>
          <TabsTrigger value="docs">
            <FileText /> 문서
          </TabsTrigger>
          <TabsTrigger value="diff">변경사항</TabsTrigger>
        </TabsList>
        <TabsContent value="tests">
          <TestResults remediation={r} />
        </TabsContent>
        <TabsContent value="docs">
          <Docs name={name} version={r.metadata.resourceVersion} />
        </TabsContent>
        <TabsContent value="diff">
          <Diff name={name} version={r.metadata.resourceVersion} enabled={!!st.baseCommit && (st.steps ?? []).some((s) => s.name === "ApplyFix" && s.state === "Succeeded")} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

const stateIcon: Record<StepState, typeof CircleCheck> = {
  Pending: CircleDashed,
  Running: LoaderCircle,
  Succeeded: CircleCheck,
  Failed: CircleX,
  Skipped: CircleSlash,
  Waiting: Hourglass,
};

const stateColor: Record<StepState, string> = {
  Pending: "text-muted-foreground",
  Running: "text-primary animate-spin",
  Succeeded: "text-emerald-500",
  Failed: "text-destructive",
  Skipped: "text-muted-foreground",
  Waiting: "text-sev-medium",
};

function duration(s: RemediationStep): string {
  if (!s.startTime || !s.completionTime) return "";
  const sec = (new Date(s.completionTime).getTime() - new Date(s.startTime).getTime()) / 1000;
  return sec < 60 ? `${sec.toFixed(1)}s` : `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
}

function Pipeline({ steps }: { steps: RemediationStep[] }) {
  const [open, setOpen] = useState<string>();
  return (
    <Card className="gap-0 py-2">
      <ol>
        {steps.map((s, i) => {
          const Icon = stateIcon[s.state];
          return (
            <li key={s.name} className={cn("px-5 py-2.5", i > 0 && "border-t")}>
              <button type="button" className="flex w-full items-center gap-3 text-left" onClick={() => setOpen(open === s.name ? undefined : s.name)} disabled={!s.log}>
                <Icon className={cn("size-5 shrink-0", stateColor[s.state])} />
                <span className="w-44 shrink-0 font-medium">{stepLabel[s.name] ?? s.name}</span>
                <span className="min-w-0 flex-1 truncate text-sm text-muted-foreground">{s.message}</span>
                <span className="shrink-0 text-xs text-muted-foreground tabular-nums">{duration(s)}</span>
                {s.log && <span className="shrink-0 text-xs text-primary">{open === s.name ? "로그 닫기" : "로그"}</span>}
              </button>
              {open === s.name && s.log && <pre className="mt-2 max-h-80 overflow-auto rounded-md bg-muted p-3 text-xs whitespace-pre-wrap">{s.log}</pre>}
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

function ReviewPanel({ remediation }: { remediation: Remediation }) {
  const [reviewer, setReviewer] = useState(() => {
    try {
      return localStorage.getItem("vulngraph-reviewer") ?? "";
    } catch {
      return "";
    }
  });
  const [comment, setComment] = useState("");
  const testsPassed = remediation.status.conditions?.find((c) => c.type === "TestsPassed")?.status === "True";
  const decide = useMutation({
    mutationFn: (approved: boolean) => api.approve(remediation.metadata.name, approved, reviewer.trim(), comment),
    onSuccess: (_, approved) => {
      try {
        localStorage.setItem("vulngraph-reviewer", reviewer.trim());
      } catch {
        // Remembering the reviewer name is a convenience only.
      }
      toast.success(approved ? "승인했습니다. PR을 생성합니다." : "반려했습니다.");
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Card className="border-primary/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="size-5 text-primary" /> 검토 및 승인
        </CardTitle>
        <CardDescription>
          변경사항·문서·테스트 결과를 확인하고 승인하면 브랜치를 push 하고 {remediation.status.kind === "Image" ? "이미지를 배포한 뒤 " : ""}PR을 생성합니다.
          {!testsPassed && <span className="font-medium text-destructive"> 실패한 테스트가 있어 승인 시 Draft PR로 생성되고 배포는 하지 않습니다.</span>}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Input value={reviewer} onChange={(e) => setReviewer(e.target.value)} placeholder="검토자 이름" className="max-w-xs" />
        <Textarea value={comment} onChange={(e) => setComment(e.target.value)} placeholder="검토 의견 (선택)" />
        <div className="flex gap-2">
          <Button disabled={!reviewer.trim() || decide.isPending} onClick={() => decide.mutate(true)}>
            <ThumbsUp /> 승인
          </Button>
          <Button variant="outline" disabled={!reviewer.trim() || decide.isPending} onClick={() => decide.mutate(false)}>
            <ThumbsDown /> 반려
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

const resultStyle = {
  Passed: { icon: CircleCheck, className: "text-emerald-500", label: "통과" },
  Failed: { icon: CircleX, className: "text-destructive", label: "실패" },
  Skipped: { icon: CircleSlash, className: "text-muted-foreground", label: "건너뜀" },
} as const;

function TestResults({ remediation }: { remediation: Remediation }) {
  const results = remediation.status.testResults ?? [];
  const [open, setOpen] = useState<string>();
  if (results.length === 0) return <p className="text-sm text-muted-foreground">테스트가 아직 실행되지 않았습니다.</p>;
  return (
    <Card className="gap-0 py-0">
      <table className="w-full text-sm">
        <thead className="border-b text-left text-xs text-muted-foreground">
          <tr>
            <th className="px-4 py-2 font-medium">ID</th>
            <th className="px-4 py-2 font-medium">시나리오</th>
            <th className="px-4 py-2 font-medium">결과</th>
            <th className="px-4 py-2 text-right font-medium">시간</th>
          </tr>
        </thead>
        <tbody>
          {results.map((t) => {
            const style = resultStyle[t.status];
            return (
              <tr key={t.id} className="cursor-pointer border-b align-top last:border-0 hover:bg-muted/40" onClick={() => setOpen(open === t.id ? undefined : t.id)}>
                <td className="px-4 py-2 font-mono text-xs">{t.id}</td>
                <td className="px-4 py-2">
                  {t.title}
                  {open === t.id && t.detail && <pre className="mt-2 max-h-64 overflow-auto rounded bg-muted p-2 text-xs whitespace-pre-wrap">{t.detail}</pre>}
                </td>
                <td className={cn("px-4 py-2 font-medium", style.className)}>
                  <span className="inline-flex items-center gap-1">
                    <style.icon className="size-4" /> {style.label}
                  </span>
                </td>
                <td className="px-4 py-2 text-right text-xs text-muted-foreground tabular-nums">{t.duration}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Card>
  );
}

function Docs({ name, version }: { name: string; version?: string }) {
  const docs = useQuery({ queryKey: ["docs", name, version], queryFn: () => api.getDocs(name), placeholderData: (p) => p });
  const files = docs.data?.files ?? [];
  if (docs.isPending) return <LoaderCircle className="size-5 animate-spin" />;
  if (files.length === 0) return <p className="text-sm text-muted-foreground">문서가 아직 작성되지 않았습니다.</p>;
  return (
    <Tabs defaultValue={files[0]?.path}>
      <TabsList>
        {files.map((f) => (
          <TabsTrigger key={f.path} value={f.path} className="font-mono text-xs">
            {f.path.split("/").pop()}
          </TabsTrigger>
        ))}
      </TabsList>
      {files.map((f) => (
        <TabsContent key={f.path} value={f.path}>
          <Card className="px-6 py-5">
            <div className="text-xs text-muted-foreground">{f.path}</div>
            <article className="markdown">
              <Markdown remarkPlugins={[remarkGfm]}>{f.content}</Markdown>
            </article>
          </Card>
        </TabsContent>
      ))}
    </Tabs>
  );
}

function Diff({ name, version, enabled }: { name: string; version?: string; enabled: boolean }) {
  const diff = useQuery({ queryKey: ["diff", name, version], queryFn: () => api.getDiff(name), enabled, placeholderData: (p) => p });
  if (!enabled) return <p className="text-sm text-muted-foreground">수정이 적용되면 변경사항이 표시됩니다.</p>;
  if (diff.isPending) return <LoaderCircle className="size-5 animate-spin" />;
  if (diff.error) return <p className="text-sm text-destructive">{diff.error.message}</p>;
  return (
    <Card className="overflow-hidden py-0">
      <pre className="max-h-[70vh] overflow-auto text-xs leading-5">
        {(diff.data ?? "").split("\n").map((line, i) => (
          <div
            // Diff lines have no identity beyond their position.
            key={i}
            className={cn(
              "px-4",
              line.startsWith("+") && !line.startsWith("+++") && "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
              line.startsWith("-") && !line.startsWith("---") && "bg-red-500/15 text-red-700 dark:text-red-300",
              line.startsWith("@@") && "bg-primary/10 text-primary",
              line.startsWith("diff --git") && "mt-2 border-t bg-muted pt-1 font-semibold",
            )}
          >
            {line || " "}
          </div>
        ))}
      </pre>
    </Card>
  );
}

export function RemediationsPage() {
  const list = useQuery({ queryKey: ["remediations"], queryFn: api.listRemediations });
  useWatch<Remediation>("remediations");
  const items = [...(list.data?.items ?? [])].sort((a, b) => (b.metadata.creationTimestamp ?? "").localeCompare(a.metadata.creationTimestamp ?? ""));
  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
      <Card className="gap-0 py-0">
        <CardHeader className="border-b py-4">
          <CardTitle>조치 목록</CardTitle>
          <CardDescription>그래프에서 취약한 노드에 마우스를 올리고 “조치”를 누르면 여기에 추가됩니다.</CardDescription>
        </CardHeader>
        {list.isPending && <LoaderCircle className="m-6 size-5 animate-spin" />}
        {list.data && items.length === 0 && <p className="p-5 text-sm text-muted-foreground">진행 중인 조치가 없습니다.</p>}
        <ul className="divide-y">
          {items.map((r) => (
            <li key={r.metadata.name}>
              <Link to="/remediations/$name" params={{ name: r.metadata.name }} className="flex items-center gap-4 px-5 py-3 hover:bg-muted/40">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-medium">{r.status.docsID}</span>
                    <span className="text-sm text-muted-foreground">
                      {r.status.component?.name} {r.status.fromVersion} → {r.status.toVersion ?? "…"}
                    </span>
                  </div>
                  <div className="truncate text-xs text-muted-foreground">
                    {r.spec.scanName} · {r.status.message} · {timeAgo(r.metadata.creationTimestamp)}
                  </div>
                </div>
                {r.status.pullRequestURL && <ExternalLink className="size-4 text-muted-foreground" />}
                <PhaseBadge phase={r.status.phase} />
              </Link>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

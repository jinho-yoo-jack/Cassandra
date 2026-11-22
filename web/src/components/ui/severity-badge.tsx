import type { Severity } from "@/lib/api";
import { cn, severityClass, severityLabel } from "@/lib/utils";

export function SeverityBadge({ severity, count, className }: { severity: Severity; count?: number; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold leading-none", severityClass[severity].badge, className)}>
      {severityLabel[severity]}
      {count !== undefined && <span className="tabular-nums opacity-90">{count}</span>}
    </span>
  );
}

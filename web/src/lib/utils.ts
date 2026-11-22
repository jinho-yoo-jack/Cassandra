import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Severity } from "./api";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export const severityRank: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  NONE: 1,
  UNKNOWN: 0,
};

export const severityLabel: Record<Severity, string> = {
  CRITICAL: "치명",
  HIGH: "높음",
  MEDIUM: "중간",
  LOW: "낮음",
  NONE: "없음",
  UNKNOWN: "미상",
};

/** Tailwind classes per severity, backed by the --sev-* theme tokens. */
export const severityClass: Record<Severity, { badge: string; border: string; text: string; stroke: string }> = {
  CRITICAL: { badge: "bg-sev-critical text-white", border: "border-sev-critical", text: "text-sev-critical", stroke: "var(--sev-critical)" },
  HIGH: { badge: "bg-sev-high text-white", border: "border-sev-high", text: "text-sev-high", stroke: "var(--sev-high)" },
  MEDIUM: { badge: "bg-sev-medium text-black", border: "border-sev-medium", text: "text-sev-medium", stroke: "var(--sev-medium)" },
  LOW: { badge: "bg-sev-low text-white", border: "border-sev-low", text: "text-sev-low", stroke: "var(--sev-low)" },
  NONE: { badge: "bg-sev-none text-white", border: "border-sev-none", text: "text-muted-foreground", stroke: "var(--sev-none)" },
  UNKNOWN: { badge: "bg-sev-none text-white", border: "border-sev-none", text: "text-muted-foreground", stroke: "var(--sev-none)" },
};

export function timeAgo(iso?: string): string {
  if (!iso) return "-";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "방금";
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`;
  return `${Math.floor(diff / 86400)}일 전`;
}

export function percent(n?: number, digits = 1): string {
  return n === undefined ? "-" : `${(n * 100).toFixed(digits)}%`;
}

export function advisoryURL(id: string): string {
  return id.startsWith("CVE-") ? `https://nvd.nist.gov/vuln/detail/${id}` : `https://osv.dev/vulnerability/${id}`;
}

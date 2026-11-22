import { create } from "zustand";
import type { Severity } from "./api";

export type ViewMode = "vulnerable" | "direct" | "all";

interface GraphState {
  view: ViewMode;
  showCode: boolean;
  showDev: boolean;
  minSeverity: Severity;
  search: string;
  selected?: string;
  setView: (v: ViewMode) => void;
  toggleCode: () => void;
  toggleDev: () => void;
  setMinSeverity: (s: Severity) => void;
  setSearch: (s: string) => void;
  select: (id?: string) => void;
}

/** UI state of the graph page; kept across navigation, not persisted. */
export const useGraphStore = create<GraphState>((set) => ({
  view: "direct",
  showCode: true,
  showDev: false,
  minSeverity: "UNKNOWN",
  search: "",
  setView: (view) => set({ view }),
  toggleCode: () => set((s) => ({ showCode: !s.showCode })),
  toggleDev: () => set((s) => ({ showDev: !s.showDev })),
  setMinSeverity: (minSeverity) => set({ minSeverity }),
  setSearch: (search) => set({ search }),
  select: (selected) => set({ selected }),
}));

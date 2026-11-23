import { getNodesBounds, getViewportForBounds, type Node } from "@xyflow/react";
import type { ExplorerMode } from "./explorer-model";

export const navigationPadding = (width: number, collapsed = width < 700) => width >= 700
  ? { top: "24px" as const, bottom: "24px" as const, left: "24px" as const, right: "300px" as const }
  : { top: "24px" as const, bottom: collapsed ? "150px" as const : "300px" as const, left: "24px" as const, right: "24px" as const };

/** Keep the chosen risk readable; the minimap still carries its complete context. */
export function initialFitNodes(nodes: Node[], mode: ExplorerMode, selected: string | undefined, width: number, height: number, collapsed: boolean) {
  if (mode !== "path" || !selected || !nodes.some(n => n.id === selected) || width <= 0 || height <= 0) return undefined;
  const viewport = getViewportForBounds(getNodesBounds(nodes), width, height, 0.04, 1, navigationPadding(width, collapsed));
  return viewport.zoom < 0.75 ? [{ id: selected }] : undefined;
}

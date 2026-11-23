import { useEffect, useState } from "react";
import { layout, type LayoutDirection } from "@/lib/graph-view";
import type { Projection } from "./explorer-model";

export function useGraphLayout(projection: Projection, direction: LayoutDirection = "RIGHT") {
  const [retry, setRetry] = useState(0);
  const [state, setState] = useState<{ source?: Projection; direction?: LayoutDirection; positions: Map<string, { x: number; y: number }>; error?: string }>({ positions: new Map() });
  useEffect(() => {
    let cancelled = false;
    setState(previous => ({ ...previous, source: undefined, error: undefined }));
    if (!projection.nodes.length) {
      setState({ source: projection, direction, positions: new Map() });
      return;
    }
    layout(projection.nodes, projection.edges, direction).then(positions => {
      if (!cancelled) setState({ source: projection, direction, positions });
    }).catch(error => {
      if (!cancelled) setState({ source: projection, direction, positions: new Map(), error: error instanceof Error ? error.message : "그래프를 배치하지 못했습니다." });
    });
    return () => { cancelled = true; };
  }, [projection, direction, retry]);
  return { ...state, loading: state.source !== projection || state.direction !== direction, retry: () => setRetry(n => n + 1) };
}

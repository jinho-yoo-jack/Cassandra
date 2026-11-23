import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { type WatchEvent, watchURL } from "@/lib/api";
import { applyWatchEvent, type Watched } from "@/lib/watch-cache";

/**
 * useWatch keeps the TanStack Query cache of a resource in sync with the
 * server's watch stream (Server-Sent Events). EventSource reconnects on its
 * own, and the server replays current objects on every (re)connect, so the
 * cache converges after network hiccups. The cache policy separately guards
 * detail updates with resourceVersion while retaining list event ordering.
 */
export function useWatch<T extends Watched>(
  resource: string,
  opts: { name?: string; enabled?: boolean; onEvent?: (e: WatchEvent<T>, previous?: T) => void } = {},
) {
  const qc = useQueryClient();
  const { name, enabled = true, onEvent } = opts;

  useEffect(() => {
    if (!enabled) return;
    const source = new EventSource(watchURL(resource, name));
    source.onmessage = (msg) => {
      const event = JSON.parse(msg.data) as WatchEvent<T>;
      const previous = applyWatchEvent(qc, resource, event);
      onEvent?.(event, previous);
    };
    return () => source.close();
  }, [qc, resource, name, enabled, onEvent]);
}

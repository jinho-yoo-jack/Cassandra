import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { type List, type ObjectMeta, type WatchEvent, watchURL } from "@/lib/api";

type Watched = { metadata: ObjectMeta };

const newer = (a?: string, b?: string) => Number(a ?? 0) >= Number(b ?? 0);

/**
 * useWatch keeps the TanStack Query cache of a resource in sync with the
 * server's watch stream (Server-Sent Events). EventSource reconnects on its
 * own, and the server replays current objects on every (re)connect, so the
 * cache converges after network hiccups. Events older than what the cache
 * holds are ignored using resourceVersion.
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
      const obj = event.object;
      const key = [resource, obj.metadata.name];
      const previous = qc.getQueryData<T>(key);
      if (event.type === "DELETED") {
        qc.removeQueries({ queryKey: key });
      } else if (!previous || newer(obj.metadata.resourceVersion, previous.metadata.resourceVersion)) {
        qc.setQueryData(key, obj);
      }
      qc.setQueryData<List<T>>([resource], (list) => {
        if (!list) return list;
        const items = list.items.filter((i) => i.metadata.name !== obj.metadata.name);
        if (event.type !== "DELETED") items.push(obj);
        items.sort((a, b) => (b.metadata.creationTimestamp ?? "").localeCompare(a.metadata.creationTimestamp ?? ""));
        return { ...list, items };
      });
      onEvent?.(event, previous);
    };
    return () => source.close();
  }, [qc, resource, name, enabled, onEvent]);
}

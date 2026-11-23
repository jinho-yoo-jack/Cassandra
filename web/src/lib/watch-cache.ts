import type { QueryClient } from "@tanstack/react-query";
import type { List, ObjectMeta, WatchEvent } from "./api-types";

export type Watched = { metadata: ObjectMeta };

const newer = (a?: string, b?: string) => Number(a ?? 0) >= Number(b ?? 0);

/**
 * Apply one parsed event and return the detail value from before the update.
 * The list intentionally accepts even older events; only detail writes are
 * version-guarded. Keep that existing policy separate from SSE lifetime.
 */
export function applyWatchEvent<T extends Watched>(qc: QueryClient, resource: string, event: WatchEvent<T>): T | undefined {
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
  return previous;
}

import assert from "node:assert/strict";
import { test } from "node:test";
import { QueryClient } from "@tanstack/react-query";
import { applyWatchEvent } from "../src/lib/watch-cache.ts";

const object = (name, resourceVersion, creationTimestamp, extra = {}) => ({
  metadata: { name, ...(resourceVersion === undefined ? {} : { resourceVersion }), ...(creationTimestamp === undefined ? {} : { creationTimestamp }) },
  ...extra,
});

// These cases characterized the hook before extraction; keep the same behavior
// assertions at the cache boundary, with hook wiring tested separately.
function cache(t, resource = "scans") {
  const qc = new QueryClient();
  t.after(() => qc.clear());
  return { qc, send: (event) => applyWatchEvent(qc, resource, event) };
}

test("ADDED seeds the detail cache but does not invent an unqueried list", (t) => {
  const { qc, send } = cache(t);
  const obj = object("a", "1");
  assert.equal(send({ type: "ADDED", object: obj }), undefined);
  assert.deepEqual(qc.getQueryData(["scans", "a"]), obj);
  assert.equal(qc.getQueryData(["scans"]), undefined);
});

test("list upsert deduplicates, sorts timestamps descending and preserves metadata", (t) => {
  const { qc, send } = cache(t);
  const a = object("a", "1", "2026-01-01");
  qc.setQueryData(["scans"], { metadata: { resourceVersion: "list-version" }, extra: true, items: [a, object("missing"), object("b", "1", "2026-02-01"), a] });
  const updated = object("a", "2", "2026-03-01");
  send({ type: "MODIFIED", object: updated });
  const list = qc.getQueryData(["scans"]);
  assert.deepEqual(list.items.map((i) => i.metadata.name), ["a", "b", "missing"]);
  assert.deepEqual(list.items[0], updated);
  assert.deepEqual(list.metadata, { resourceVersion: "list-version" });
  assert.equal(list.extra, true);
});

test("equal-timestamp update keeps stable sort with updated object appended", (t) => {
  const { qc, send } = cache(t);
  qc.setQueryData(["scans"], { metadata: {}, items: [object("a", "1", "date"), object("b", "1", "date")] });
  send({ type: "MODIFIED", object: object("a", "2", "date") });
  assert.deepEqual(qc.getQueryData(["scans"]).items.map((i) => i.metadata.name), ["b", "a"]);
});

for (const [previousVersion, incomingVersion, replaced] of [
  ["9", "10", true], ["10", "9", false], ["10", "10", true],
  [undefined, undefined, true], [undefined, "1", true], ["1", undefined, false],
  ["not-numeric", "10", false], ["10", "not-numeric", false],
  ["9007199254740993", "9007199254740992", true],
]) {
  test(`detail version comparison uses Number >=: ${previousVersion} -> ${incomingVersion}`, (t) => {
    const { qc, send } = cache(t);
    const old = object("a", previousVersion, undefined, { value: "old" });
    qc.setQueryData(["scans", "a"], old);
    const incoming = object("a", incomingVersion, undefined, { value: "new" });
    assert.equal(send({ type: "MODIFIED", object: incoming }), old);
    assert.deepEqual(qc.getQueryData(["scans", "a"]), replaced ? incoming : old);
  });
}

test("older event still replaces the list entry while detail stays newer (existing policy)", (t) => {
  const { qc, send } = cache(t);
  const old = object("a", "20", "2026-02-01");
  qc.setQueryData(["scans", "a"], old);
  qc.setQueryData(["scans"], { metadata: { resourceVersion: "30" }, items: [old] });
  const incoming = object("a", "10", "2026-01-01");
  assert.equal(send({ type: "MODIFIED", object: incoming }), old);
  assert.equal(qc.getQueryData(["scans", "a"]), old);
  assert.deepEqual(qc.getQueryData(["scans"]).items, [incoming]);
  assert.equal(qc.getQueryData(["scans"]).metadata.resourceVersion, "30");
});

test("DELETED removes detail-key prefixes regardless of version, not unrelated keys", (t) => {
  const { qc, send } = cache(t);
  const old = object("a", "20");
  qc.setQueryData(["scans", "a"], old);
  qc.setQueryData(["scans", "a", "child"], { nested: true });
  qc.setQueryData(["scans", "ab"], { retained: true });
  qc.setQueryData(["graphs", "a"], { retained: true });
  qc.setQueryData(["scans"], { metadata: { resourceVersion: "30" }, items: [old, object("b", "1")] });
  assert.equal(send({ type: "DELETED", object: object("a", "1") }), old);
  assert.equal(qc.getQueryData(["scans", "a"]), undefined);
  assert.equal(qc.getQueryData(["scans", "a", "child"]), undefined);
  assert.deepEqual(qc.getQueryData(["scans", "ab"]), { retained: true });
  assert.deepEqual(qc.getQueryData(["graphs", "a"]), { retained: true });
  assert.deepEqual(qc.getQueryData(["scans"]).items.map((i) => i.metadata.name), ["b"]);
});

test("cache policy is resource-generic and keeps other resource lists untouched", (t) => {
  const { qc, send } = cache(t, "feeds");
  qc.setQueryData(["feeds"], { metadata: {}, items: [] });
  const scans = { metadata: {}, items: [object("a", "2")] };
  qc.setQueryData(["scans"], scans);
  const feed = object("a", "3", undefined, { status: { processed: 2 } });
  send({ type: "ADDED", object: feed });
  assert.deepEqual(qc.getQueryData(["feeds", "a"]), feed);
  assert.deepEqual(qc.getQueryData(["feeds"]).items, [feed]);
  assert.equal(qc.getQueryData(["scans"]), scans);
});

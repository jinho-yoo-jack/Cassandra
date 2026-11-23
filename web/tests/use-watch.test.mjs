import assert from "node:assert/strict";
import { test } from "node:test";
import { API_ROOT } from "../src/lib/api.ts";
import { mountWatch, QueryClient } from "./watch-harness.mjs";

function mount(t, options = {}) {
  const qc = new QueryClient();
  const watch = mountWatch(qc, "scans", options);
  t.after(() => { watch.close(); qc.clear(); });
  return { qc, watch };
}

test("useWatch opens the scoped SSE URL and closes the source on unmount", (t) => {
  const { watch } = mount(t, { name: "a/b c" });
  const source = watch.source;
  assert.equal(source.url, `${API_ROOT}/scans?watch=true&fieldSelector=metadata.name%3Da%2Fb+c`);
  assert.equal(source.closed, 0);
  watch.close();
  assert.equal(source.closed, 1);
});

test("disabled watches do not open a source; enabling and disabling cleans up", (t) => {
  const { watch } = mount(t, { enabled: false });
  assert.equal(watch.sources.length, 0);
  watch.render("scans", { enabled: true });
  assert.equal(watch.sources.length, 1);
  const source = watch.source;
  watch.render("scans", { enabled: false });
  assert.equal(source.closed, 1);
  assert.equal(watch.sources.length, 1);
});

test("onEvent receives the pre-update detail after both caches are updated", (t) => {
  const previous = { metadata: { name: "a", resourceVersion: "1" } };
  const incoming = { metadata: { name: "a", resourceVersion: "2" } };
  const seen = [];
  const { qc, watch } = mount(t, { onEvent(event, old) {
    seen.push(event);
    assert.equal(old, previous);
    assert.deepEqual(qc.getQueryData(["scans", "a"]), incoming);
    assert.deepEqual(qc.getQueryData(["scans"]).items, [incoming]);
  } });
  qc.setQueryData(["scans", "a"], previous);
  qc.setQueryData(["scans"], { metadata: {}, items: [previous] });
  const event = { type: "MODIFIED", object: incoming };
  watch.source.emit(event);
  assert.deepEqual(seen, [event]);
});

test("callback changes still resubscribe, while identical dependencies reuse source", (t) => {
  const onEvent = () => {};
  const { watch } = mount(t, { onEvent });
  const first = watch.source;
  watch.render("scans", { onEvent });
  assert.equal(watch.sources.length, 1);
  watch.render("scans", { onEvent: () => {} });
  assert.equal(first.closed, 1);
  assert.equal(watch.sources.length, 2);
});

test("resource, name and QueryClient dependency changes close the prior source", (t) => {
  const { watch } = mount(t);
  const first = watch.source;
  watch.render("remediations", { name: "a" });
  assert.equal(first.closed, 1);
  assert.equal(watch.source.url, `${API_ROOT}/remediations?watch=true&fieldSelector=metadata.name%3Da`);
  const second = watch.source;
  watch.render("remediations", { name: "b" });
  assert.equal(second.closed, 1);
  const third = watch.source;
  const nextClient = new QueryClient();
  t.after(() => nextClient.clear());
  watch.render("remediations", { name: "b" }, nextClient);
  assert.equal(third.closed, 1);
  watch.source.emit({ type: "ADDED", object: { metadata: { name: "b" } } });
  assert.deepEqual(nextClient.getQueryData(["remediations", "b"]), { metadata: { name: "b" } });
});

test("malformed SSE JSON propagates without updating caches or invoking callback", (t) => {
  let called = false;
  const { qc, watch } = mount(t, { onEvent: () => { called = true; } });
  assert.throws(() => watch.source.onmessage({ data: "invalid" }), SyntaxError);
  assert.equal(called, false);
  assert.equal(qc.getQueryCache().getAll().length, 0);
});

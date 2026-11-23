import assert from "node:assert/strict";
import { mock, test } from "node:test";

let slots, cursor, effect, deps, cleanup, previousDeps;
const requests = [];
mock.module("react", { exports: {
  useState(initial) { const i = cursor++; if (!(i in slots)) slots[i] = initial; return [slots[i], value => { slots[i] = typeof value === "function" ? value(slots[i]) : value; }]; },
  useEffect(fn, next) { effect = fn; deps = next; },
} });
mock.module(new URL("../src/lib/graph-view.ts", import.meta.url).href, { exports: { layout: (_nodes, _edges, direction) => new Promise((resolve, reject) => requests.push({ resolve, reject, direction })) } });
const { useGraphLayout } = await import("../src/components/graph/use-graph-layout.ts");
const projection = id => ({ nodes: [{ id }], edges: [], onPath: new Map() });
function mount() {
  slots = []; requests.length = 0; cleanup = undefined; previousDeps = undefined;
  return (source, direction) => {
    cursor = 0;
    const value = useGraphLayout(source, direction);
    if (!previousDeps || deps.some((d, i) => d !== previousDeps[i])) { cleanup?.(); cleanup = effect(); previousDeps = deps; }
    return value;
  };
}
const flush = () => new Promise(resolve => setImmediate(resolve));

test("direction changes invalidate stale positions for the same projection", async () => {
  const render = mount(), source = projection("a");
  render(source, "RIGHT");
  requests[0].resolve(new Map([["a", { x: 1, y: 1 }]])); await flush();
  assert.equal(render(source, "RIGHT").loading, false);
  assert.equal(render(source, "DOWN").loading, true);
  assert.equal(requests.length, 2);
  assert.equal(requests[1].direction, "DOWN");
  requests[1].resolve(new Map([["a", { x: 0, y: 200 }]])); await flush();
  assert.equal(render(source, "DOWN").loading, false);
  cleanup?.();
});

test("layout exposes loading, ignores stale completion and does not restart for unchanged structural input", async () => {
  const render = mount(), a = projection("a"), b = projection("b");
  assert.equal(render(a).loading, true);
  render(a); assert.equal(requests.length, 1);
  render(b); assert.equal(requests.length, 2);
  requests[0].resolve(new Map([["a", { x: 1, y: 1 }]])); await flush();
  assert.equal(render(b).loading, true);
  const positions = new Map([["b", { x: 2, y: 2 }]]);
  requests[1].resolve(positions); await flush();
  assert.equal(render(b).positions, positions);
  assert.equal(render(b).loading, false);
  cleanup?.();
});

test("layout failure is visible, retry clears error and empty projection never calls ELK", async () => {
  const render = mount(), a = projection("a");
  render(a); requests[0].reject(new Error("layout failed")); await flush();
  assert.equal(render(a).error, "layout failed");
  render(a).retry(); render(a);
  assert.equal(render(a).error, undefined);
  assert.equal(render(a).loading, true);
  requests[1].resolve(new Map()); await flush();
  assert.equal(render(a).loading, false);
  const empty = { nodes: [], edges: [], onPath: new Map() };
  render(empty); assert.equal(render(empty).loading, false);
  assert.equal(requests.length, 2);
  cleanup?.();
});

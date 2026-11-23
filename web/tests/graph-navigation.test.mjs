import assert from "node:assert/strict";
import { test } from "node:test";
import { navigationPadding } from "../src/components/graph/graph-navigation.ts";
import * as navigation from "../src/components/graph/graph-navigation.ts";
import { layout } from "../src/lib/graph-view.ts";

test("narrow canvases reserve the navigator's full height, with a compact collapsed alternative", () => {
  assert.equal(navigationPadding(508, false).bottom, "300px");
  assert.equal(navigationPadding(375, true).bottom, "150px");
  assert.equal(navigationPadding(1100, false).right, "300px");
});

test("selected dependency paths can be laid out vertically instead of shrinking a wide chain", async () => {
  const nodes = ["repo", "manifest", "image", "process"].map(id => ({ id, label: id, kind: "library" }));
  const edges = nodes.slice(1).map((n, i) => ({ id: `e${i}`, source: nodes[i].id, target: n.id, kind: "dependsOn" }));
  const positions = await layout(nodes, edges, "DOWN");
  for (let i = 1; i < nodes.length; i++) {
    assert.ok(positions.get(nodes[i].id).y > positions.get(nodes[i - 1].id).y, "path must advance downward");
  }
});

test("auto-fit focuses a selected risk when fitting its full context would make labels unreadable", () => {
  const nodes = Array.from({ length: 4 }, (_, i) => ({ id: String(i), position: { x: i * 360, y: 0 }, width: 264, height: 96, data: {} }));
  assert.equal(typeof navigation.initialFitNodes, "function", "a readable-path fit policy is required");
  assert.deepEqual(navigation.initialFitNodes(nodes, "path", "3", 800, 648, false), [{ id: "3" }]);
  assert.equal(navigation.initialFitNodes(nodes, "overview", "3", 800, 648, false), undefined);
  assert.equal(navigation.initialFitNodes(nodes, "path", "missing", 800, 648, false), undefined);
  const vertical = nodes.map((n, i) => ({ ...n, position: { x: 0, y: i * 180 } }));
  assert.equal(navigation.initialFitNodes(vertical, "path", "3", 800, 648, false), undefined);
});

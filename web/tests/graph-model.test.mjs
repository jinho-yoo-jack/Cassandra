import assert from "node:assert/strict";
import { test } from "node:test";
import { MarkerType } from "@xyflow/react";
import { buildFlowGraph, connected, decorateNodes, searchHits } from "../src/components/graph/graph-model.ts";
import { layout, nodeSeverity, visibleGraph, vulnerablePaths } from "../src/lib/graph-view.ts";
import { severityClass } from "../src/lib/utils.ts";

const finding = (severity) => ({ severity, vulnerabilityID: `id-${severity}`, displayID: `id-${severity}` });
const node = (id, kind = "library", extra = {}) => ({ id, kind, label: id, ...extra });
const edge = (source, target, kind = "depends") => ({ id: `${source}-${target}`, source, target, kind });
const options = { view: "all", showCode: true, showDev: false, minSeverity: "HIGH" };

function fixture() {
  return {
    metadata: { name: "scan" },
    nodes: [
      node("repo", "repository"), node("project", "project"), node("code", "package"),
      node("direct", "library", { direct: true, findings: [finding("HIGH"), finding("LOW")], fixTarget: "3.2" }),
      node("transitive", "library", { findings: [finding("CRITICAL")] }),
      node("unused", "library", { findings: [finding("LOW")] }),
      node("dev", "library", { dev: true, direct: true, findings: [finding("CRITICAL")] }),
      node("image", "image", { direct: true }), node("process", "process"), node("indirectProcess", "process"),
    ],
    edges: [
      edge("repo", "project", "contains"), edge("project", "code", "contains"), edge("code", "direct", "imports"),
      edge("direct", "transitive"), edge("project", "unused"), edge("project", "dev"),
      edge("project", "image"), edge("image", "process", "runs"), edge("project", "indirectProcess", "runs"),
    ],
  };
}

function freeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) freeze(child);
  }
  return value;
}
const ids = (nodes) => nodes.map((n) => n.id);

test("node severity comes from findings above the threshold, not summary severity", () => {
  assert.equal(nodeSeverity(node("a", "library", { severity: "CRITICAL" }), "UNKNOWN"), undefined);
  const n = node("a", "library", { findings: [finding("LOW"), finding("HIGH"), finding("MEDIUM")] });
  assert.equal(nodeSeverity(n, "MEDIUM"), "HIGH");
  assert.equal(nodeSeverity(n, "CRITICAL"), undefined);
  assert.equal(nodeSeverity(node("a", "library", { findings: [finding("UNKNOWN"), finding("NONE")] }), "UNKNOWN"), "NONE");
});

test("vulnerable paths terminate on cycles and propagate the worst reachable finding backwards", () => {
  const graph = {
    metadata: { name: "cycle" },
    nodes: [node("root"), node("a"), node("b", "library", { findings: [finding("HIGH")] }), node("c", "library", { findings: [finding("CRITICAL")] }), node("clean")],
    edges: [edge("root", "a"), edge("a", "b"), edge("b", "a"), edge("a", "c"), edge("root", "clean")],
  };
  const paths = vulnerablePaths(freeze(graph), "HIGH");
  assert.deepEqual(Object.fromEntries(paths), { b: "CRITICAL", c: "CRITICAL", a: "CRITICAL", root: "CRITICAL" });
  assert.equal(paths.has("clean"), false);
});

for (const [view, expected] of [
  ["all", ["repo", "project", "code", "direct", "transitive", "unused", "image", "process", "indirectProcess"]],
  ["direct", ["repo", "project", "code", "direct", "transitive", "image", "process"]],
  ["vulnerable", ["direct", "transitive"]],
]) {
  test(`${view} view preserves toolbar filtering and drops edges with hidden endpoints`, () => {
    const graph = freeze(fixture());
    const visible = visibleGraph(graph, { ...options, view });
    assert.deepEqual(ids(visible.nodes), expected);
    assert.deepEqual(visible.edges, graph.edges.filter((e) => expected.includes(e.source) && expected.includes(e.target)));
    assert.equal(visible.nodes[0], graph.nodes.find(n => n.id === expected[0]));
  });
}

test("direct view includes processes run by direct images even without findings", () => {
  const visible = visibleGraph(fixture(), { ...options, view: "direct" });
  assert.ok(ids(visible.nodes).includes("process"));
  assert.ok(!ids(visible.nodes).includes("indirectProcess"));
  assert.equal(visible.onPath.has("process"), false);
  assert.ok(visible.edges.some((e) => e.id === "image-process"));
});

test("code/dev toggles only filter their nodes and edges; hidden findings still contribute to paths", () => {
  const graph = fixture();
  const hidden = visibleGraph(graph, { ...options, showCode: false });
  assert.ok(!ids(hidden.nodes).includes("code"));
  assert.ok(!hidden.edges.some((e) => e.source === "code" || e.target === "code"));
  assert.equal(hidden.onPath.get("dev"), "CRITICAL");
  assert.ok(ids(visibleGraph(graph, { ...options, showDev: true }).nodes).includes("dev"));
  assert.ok(ids(visibleGraph(graph, { ...options, view: "vulnerable", minSeverity: "LOW" }).nodes).includes("unused"));
});

test("vulnerable view excludes healthy repository/project scaffolding", () => {
  const graph = { metadata: {}, nodes: [node("r", "repository"), node("p", "project"), node("c", "package"), node("lib")], edges: [edge("r", "p", "contains"), edge("p", "c", "contains")] };
  assert.deepEqual(ids(visibleGraph(graph, { ...options, view: "vulnerable" }).nodes), []);
});

test("flow model preserves node identity, positions, fixTarget and threshold counts", () => {
  const visible = visibleGraph(freeze(fixture()), options);
  const positions = new Map([["direct", { x: 123, y: 456 }]]);
  const result = buildFlowGraph(visible, positions, "HIGH");
  const direct = result.nodes.find((n) => n.id === "direct");
  assert.deepEqual(direct, { id: "direct", type: "vg", width: 264, height: 96, position: { x: 123, y: 456 }, data: { node: visible.nodes.find((n) => n.id === "direct"), severity: "HIGH", findingCount: 1, dimmed: false, highlighted: false } });
  assert.equal(direct.position, positions.get("direct"));
  assert.equal(direct.data.node, visible.nodes.find((n) => n.id === "direct"));
  assert.equal(direct.data.node.fixTarget, "3.2");
  assert.deepEqual(result.nodes[0].position, { x: 0, y: 0 });
  assert.equal(result.nodes[0].data.severity, undefined);
  assert.equal(buildFlowGraph(visible, positions, "CRITICAL").nodes.find((n) => n.id === "direct").data.findingCount, 0);
});

test("edge model retains color and dashes without blanket risk animation", () => {
  const result = buildFlowGraph(visibleGraph(fixture(), options), new Map(), "HIGH");
  const hot = result.edges.find((e) => e.id === "code-direct");
  assert.deepEqual(hot, {
    id: "code-direct", source: "code", target: "direct", animated: false,
    style: { stroke: severityClass.CRITICAL.stroke, strokeWidth: 2, strokeDasharray: "5 4", opacity: 0.95 },
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: severityClass.CRITICAL.stroke },
  });
  const contains = result.edges.find((e) => e.id === "repo-project");
  assert.equal(contains.animated, false);
  assert.deepEqual(contains.style, { stroke: undefined, strokeWidth: 1, strokeDasharray: undefined, opacity: 0.45 });
  assert.equal(contains.markerEnd.color, undefined);
  assert.equal(result.edges.find((e) => e.id === "image-process").animated, false);
});

for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]) {
  test(`edge severity ${severity} retains run-edge color without animation`, () => {
    const visible = { nodes: [node("image"), node("process")], edges: [edge("image", "process", "runs")], onPath: new Map([["process", severity]]) };
    const [result] = buildFlowGraph(visible, new Map(), "UNKNOWN").edges;
    assert.equal(result.animated, false);
    assert.equal(result.style.stroke, severityClass[severity].stroke);
    assert.equal(result.style.strokeWidth, 2);
    assert.equal(result.style.opacity, 0.95);
  });
}

test("selection includes ancestors and descendants but not siblings, even with cycles", () => {
  const edges = [edge("r", "a"), edge("a", "b"), edge("a", "sibling"), edge("b", "c"), edge("c", "b"), edge("x", "b"), edge("z", "x")];
  assert.deepEqual(connected(edges, "b"), new Set(["b", "c", "a", "x", "r", "z"]));
  assert.deepEqual(connected(edges, "missing"), new Set(["missing"]));
  const nodes = buildFlowGraph({ nodes: [node("b"), node("c"), node("sibling")], edges, onPath: new Map() }, new Map(), "HIGH").nodes;
  const selected = decorateNodes(freeze(nodes), edges, "b", "");
  assert.equal(selected[0], nodes[0]);
  assert.equal(selected[1], nodes[1]);
  assert.equal(selected[2].data.dimmed, true);
  assert.equal(nodes[2].data.dimmed, false);
  assert.ok(decorateNodes(selected, edges, undefined, "").every((n) => !n.data.dimmed));
});

test("search highlights label or purl with trim/case folding but navigates label only", () => {
  const nodes = buildFlowGraph({ nodes: [node("label", "library", { label: "Library Alpha" }), node("purl", "library", { purl: "pkg:npm/ALPHA@1" }), node("none")], edges: [], onPath: new Map() }, new Map(), "HIGH").nodes;
  const highlighted = decorateNodes(freeze(nodes), [], undefined, "  ALpHa  ");
  assert.deepEqual(highlighted.map((n) => n.data.highlighted), [true, true, false]);
  assert.deepEqual(searchHits(nodes, " ALpHa "), [{ id: "label" }]);
  assert.deepEqual(searchHits(nodes, "pkg:npm"), []);
  assert.equal(highlighted[2], nodes[2]);
  assert.equal(decorateNodes(highlighted, [], undefined, "alpha")[0], highlighted[0]);
});

test("empty search clears highlights but its navigation includes all labels", () => {
  const nodes = buildFlowGraph({ nodes: [node("a"), node("b")], edges: [], onPath: new Map() }, new Map(), "HIGH").nodes;
  const highlighted = decorateNodes(nodes, [], undefined, "a");
  assert.ok(decorateNodes(highlighted, [], undefined, "   ").every((n) => !n.data.highlighted));
  assert.deepEqual(searchHits(nodes, "   "), [{ id: "a" }, { id: "b" }]);
});

test("empty graph yields empty visible and flow models", () => {
  const visible = visibleGraph({ metadata: {}, nodes: [], edges: [] }, options);
  assert.deepEqual(visible, { nodes: [], edges: [], onPath: new Map() });
  assert.deepEqual(buildFlowGraph(visible, new Map(), "HIGH"), { nodes: [], edges: [] });
  assert.deepEqual(decorateNodes([], [], "missing", "a"), []);
  assert.deepEqual(searchHits([], ""), []);
});

test("actual lazy ELK layout returns finite left-to-right positions without mutating the graph", async () => {
  const graph = freeze({ nodes: [node("r", "repository"), node("p", "project"), node("lib")], edges: [edge("r", "p", "contains"), edge("p", "lib")] });
  const positions = await layout(graph.nodes, graph.edges);
  assert.equal(positions.size, graph.nodes.length);
  for (const n of graph.nodes) {
    assert.ok(Number.isFinite(positions.get(n.id).x));
    assert.ok(Number.isFinite(positions.get(n.id).y));
  }
  assert.ok(positions.get("r").x < positions.get("p").x);
  assert.ok(positions.get("p").x < positions.get("lib").x);
  assert.deepEqual(await layout(graph.nodes, graph.edges), positions);
});

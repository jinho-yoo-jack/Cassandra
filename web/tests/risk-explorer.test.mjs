import assert from "node:assert/strict";
import { test } from "node:test";
import { rankRisks, indexGraph, projectGraph, summarizeGroups, filterProjection } from "../src/components/graph/explorer-model.ts";

export const node = (id, extra = {}) => ({ id, kind: "library", label: id, ...extra });
export const finding = (severity, extra = {}) => ({ severity, vulnerabilityID: "CVE-1", displayID: "CVE-1", ...extra });
export const edge = (source, target) => ({ id: `${source}-${target}`, source, target, kind: "depends" });
function fixture() {
  return { metadata: { name: "test" }, nodes: [
    node("r", { kind: "repository" }), node("p", { kind: "project", path: "package.json" }), node("p2", { kind: "project" }),
    node("a", { direct: true }), node("b", { findings: [finding("HIGH"), finding("LOW")] }),
    node("leaf"), node("sibling"), node("orphan", { findings: [finding("CRITICAL")] }),
  ], edges: [edge("r", "p"), edge("r", "p2"), edge("p", "a"), edge("a", "b"), edge("p2", "b"), edge("b", "leaf"), edge("a", "sibling")] };
}
const ids = projection => projection.nodes.map(n => n.id);

test("overview is real scaffolding; expansion reveals one level and collapse removes hidden descendants", () => {
  const g = fixture(), index = indexGraph(g);
  assert.deepEqual(ids(projectGraph(index, "overview", new Set())), ["r", "p", "p2"]);
  assert.deepEqual(ids(projectGraph(index, "overview", new Set(["p"]))), ["r", "p", "p2", "a"]);
  assert.deepEqual(ids(projectGraph(index, "overview", new Set(["p", "a"]))), ["r", "p", "p2", "a", "b", "sibling"]);
  assert.deepEqual(ids(projectGraph(index, "overview", new Set(["a"]))), ["r", "p", "p2"]);
  assert.equal(projectGraph(index, "overview", new Set(["p"])).nodes.at(-1), g.nodes[3]);
});

test("group counts deduplicate shared/cyclic dependencies and keep orphan findings visible in totals", () => {
  const g = fixture(); g.edges.push(edge("leaf", "a"));
  const index = indexGraph(g), groups = summarizeGroups(index, rankRisks(g.nodes, filters));
  assert.equal(groups.get("p").members, 4);
  assert.equal(groups.get("p").vulnerableComponents, 1);
  assert.equal(groups.get("p").findings, 2);
  assert.equal(groups.get("r").vulnerableComponents, 1);
  assert.equal(index.orphanFindings, 1);
  assert.equal(index.orphanComponents, 1);
});

test("strict mode contains findings only, selected context contains only ancestors (cycle safe), no sibling/descendant", () => {
  const index = indexGraph(fixture());
  assert.deepEqual(ids(projectGraph(index, "vulnerable", new Set())), ["b", "orphan"]);
  assert.deepEqual(ids(projectGraph(index, "path", new Set(), "b")), ["r", "p", "p2", "a", "b"]);
  index.graph.edges.push(edge("b", "a"));
  assert.deepEqual(ids(projectGraph(indexGraph(index.graph), "path", new Set(), "b")), ["r", "p", "p2", "a", "b"]);
  assert.deepEqual(ids(projectGraph(index, "path", new Set(), "missing")), ["r", "p", "p2"]);
});

test("filter projection reuses geometry nodes, excludes nonmatches and drops dangling edges", () => {
  const index = indexGraph(fixture());
  const base = projectGraph(index, "vulnerable", new Set());
  const rows = rankRisks(index.graph.nodes, { ...filters, search: "orphan" });
  const filtered = filterProjection(index, base, rows, "vulnerable", true);
  assert.deepEqual(ids(filtered), ["orphan"]);
  assert.equal(filtered.nodes[0], base.nodes[1]);
  assert.deepEqual(filtered.edges, []);
  assert.deepEqual(ids(filterProjection(index, base, [], "vulnerable", true)), []);
});

import { validSelection } from "../src/components/graph/explorer-model.ts";

test("selection invalidates hidden dev/code nodes and foreign scan IDs", () => {
  const g = fixture(); g.nodes.find(n => n.id === "b").dev = true;
  const index = indexGraph(g), withoutDev = { ...filters, showDev: false };
  assert.equal(validSelection(index, rankRisks(g.nodes, withoutDev), "b", withoutDev), undefined);
  assert.equal(validSelection(index, rankRisks(g.nodes, filters), "foreign-scan-id", filters), undefined);
  assert.equal(validSelection(index, rankRisks(g.nodes, filters), "b", filters), "b");
  assert.equal(validSelection(index, [], "a", filters), "a");
});

export const filters = { minSeverity: "UNKNOWN", kevOnly: false, search: "", showDev: true, showCode: true };

test("risk order explains KEV, matching severity, EPSS, fix availability and deterministic identity ties", () => {
  const nodes = [
    node("unknown", { findings: [finding("HIGH")] }),
    node("z", { findings: [finding("HIGH", { epss: 0, fixedVersion: "2" })] }),
    node("b", { findings: [finding("HIGH", { epss: 0.2 })] }),
    node("a", { findings: [finding("HIGH", { epss: 0.2 })] }),
    node("critical", { findings: [finding("CRITICAL", { epss: 0.1 })] }),
    node("kev", { findings: [finding("LOW", { knownExploited: true })] }),
    node("fixed", { findings: [finding("HIGH", { epss: 0.2, fixedVersion: "2" })] }),
  ];
  const rows = rankRisks(nodes, filters);
  assert.deepEqual(rows.map(r => r.node.id), ["kev", "critical", "fixed", "a", "b", "z", "unknown"]);
  assert.equal(rows.at(-1).epss, undefined);
  assert.equal(rows.find(r => r.node.id === "z").epss, 0);
  assert.equal(rows[0].kev, true);
  assert.equal(rows[2].fixable, true);
});

test("severity/KEV/search intersect on the same finding, never mixed evidence from a component", () => {
  const n = node("mixed", { fixTarget: "9", findings: [
    finding("CRITICAL", { displayID: "critical", epss: 0.9, fixedVersion: "9" }),
    finding("LOW", { displayID: "low-kev", knownExploited: true }),
  ] });
  assert.equal(rankRisks([n], { ...filters, minSeverity: "HIGH", kevOnly: true }).length, 0);
  const rows = rankRisks([n], { ...filters, search: "LOW-KEV" });
  assert.equal(rows[0].severity, "LOW");
  assert.equal(rows[0].findings.length, 1);
  assert.equal(rows[0].epss, undefined);
  assert.equal(rows[0].fixable, false);
  assert.equal(rows[0].node, n);
  assert.equal(rankRisks([n], { ...filters, search: "not-found" }).length, 0);
});

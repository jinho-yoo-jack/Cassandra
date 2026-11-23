import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, before, beforeEach, mock, test } from "node:test";
import { api, ApiError, API_ROOT, watchURL } from "../src/lib/api.ts";
import { ApiError as TransportError, request, requestText } from "../src/lib/http.ts";

// Exercise the actual facade, transport and fetch against a local HTTP server.
// Only the browser's implicit origin is supplied by this adapter.
let response;
let requests;
let calls;
const server = createServer(async (req, res) => {
  let body = "";
  for await (const chunk of req) body += chunk;
  requests.push({ url: req.url, method: req.method, accept: req.headers.accept, contentType: req.headers["content-type"], body });
  res.writeHead(response.code, response.statusText);
  res.end(response.body);
});

before(async () => {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const fetch = globalThis.fetch;
  mock.method(globalThis, "fetch", (url, init) => {
    calls.push({ url, init });
    return fetch(new URL(url, origin), init);
  });
});
beforeEach(() => {
  response = { code: 200, statusText: "OK", body: '{"ok":true}' };
  requests = [];
  calls = [];
});
after(async () => {
  mock.restoreAll();
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

const spec = { scanName: "scan", vulnerabilityID: "CVE-1", componentID: "pkg:abc", targetVersion: "2.0", deploy: { namespace: "n", deployment: "d", container: "c" } };
for (const [name, run, path, method = "GET", body] of [
  ["listScans", () => api.listScans(), "/scans"],
  ["getScan", () => api.getScan("raw/name"), "/scans/raw/name"],
  ["createScan without ref", () => api.createScan("https://example.com/repo"), "/scans", "POST", { spec: { repositoryURL: "https://example.com/repo" } }],
  ["createScan with ref", () => api.createScan("repo", "feature/a"), "/scans", "POST", { spec: { repositoryURL: "repo", ref: "feature/a" } }],
  ["deleteScan", () => api.deleteScan("scan"), "/scans/scan", "DELETE"],
  ["getGraph", () => api.getGraph("scan"), "/scans/scan/graph"],
  ["getVulnerability encodes its ID", () => api.getVulnerability("CVE/a ?한"), "/vulnerabilities/CVE%2Fa%20%3F%ED%95%9C"],
  ["listRemediations", () => api.listRemediations(), "/remediations"],
  ["getRemediation", () => api.getRemediation("rem"), "/remediations/rem"],
  ["createRemediation", () => api.createRemediation(spec), "/remediations", "POST", { spec }],
  ["deleteRemediation", () => api.deleteRemediation("rem"), "/remediations/rem", "DELETE"],
  ["approve", () => api.approve("rem", true, "reviewer", "ok"), "/remediations/rem/approval", "POST", { approved: true, reviewer: "reviewer", comment: "ok" }],
  ["deny", () => api.approve("rem", false, "", ""), "/remediations/rem/approval", "POST", { approved: false, reviewer: "", comment: "" }],
  ["getDocs", () => api.getDocs("rem"), "/remediations/rem/docs"],
  ["listFeeds", () => api.listFeeds(), "/feeds"],
]) {
  test(`${name}: URL, verb, JSON body and headers`, async () => {
    assert.deepEqual(await run(), { ok: true });
    assert.deepEqual(requests, [{ url: API_ROOT + path, method, accept: "application/json", contentType: body ? "application/json" : undefined, body: body ? JSON.stringify(body) : "" }]);
    assert.equal(calls[0].url, API_ROOT + path);
    assert.equal(calls[0].init.method, method === "GET" ? undefined : method);
  });
}

test("JSON transport returns undefined for an empty successful body", async () => {
  response = { code: 204, statusText: "No Content", body: "" };
  assert.equal(await api.deleteScan("scan"), undefined);
});

test("JSON transport does not conceal malformed success JSON", async () => {
  response.body = "not JSON";
  await assert.rejects(api.getScan("scan"), SyntaxError);
});

test("JSON transport retains every structured status field", async () => {
  const status = { kind: "Status", status: "Failure", message: "denied", reason: "Forbidden", code: 403, details: { causes: [{ field: "spec", message: "bad" }] } };
  response = { code: 403, statusText: "Forbidden", body: JSON.stringify(status) };
  await assert.rejects(api.getScan("scan"), (error) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.message, "denied");
    assert.deepEqual(error.status, status);
    return true;
  });
});

for (const [body, message] of [["upstream unavailable", "upstream unavailable"], ["", "Service Unavailable"]]) {
  test(`JSON transport falls back to ${body ? "raw text" : "status text"} on non-JSON errors`, async () => {
    response = { code: 503, statusText: "Service Unavailable", body };
    await assert.rejects(api.listFeeds(), (error) => {
      assert.ok(error instanceof ApiError);
      assert.deepEqual(error.status, { kind: "Status", status: "Failure", message, code: 503 });
      return true;
    });
  });
}

test("JSON errors are not schema-validated or replaced with fallback status", async () => {
  response = { code: 500, statusText: "Failure", body: '{"custom":true}' };
  await assert.rejects(api.listFeeds(), (error) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.message, "");
    assert.deepEqual(error.status, { custom: true });
    return true;
  });
});

test("getDiff uses bare fetch and returns text unchanged, including empty text", async () => {
  response.body = "diff --git a/a b/a\n+한글\n";
  assert.equal(await api.getDiff("raw/name"), response.body);
  assert.deepEqual(calls, [{ url: `${API_ROOT}/remediations/raw/name/diff`, init: undefined }]);
  assert.equal(requests[0].accept, "*/*");
  assert.equal(requests[0].contentType, undefined);
  response.body = "";
  assert.equal(await api.getDiff("rem"), "");
});

test("getDiff wraps structured errors in the same ApiError class", async () => {
  const status = { kind: "Status", status: "Failure", message: "no diff", code: 404 };
  response = { code: 404, statusText: "Not Found", body: JSON.stringify(status) };
  await assert.rejects(api.getDiff("rem"), (error) => error instanceof ApiError && error.message === "no diff" && assert.deepEqual(error.status, status) === undefined);
});

for (const body of ["not JSON", ""]) {
  test(`getDiff deliberately propagates JSON parse failure for error body ${JSON.stringify(body)}`, async () => {
    response = { code: 502, statusText: "Bad Gateway", body };
    await assert.rejects(api.getDiff("rem"), SyntaxError);
  });
}

test("transport propagates network rejection unchanged", async (t) => {
  const error = new TypeError("network unavailable");
  t.mock.method(globalThis, "fetch", async () => { throw error; });
  await assert.rejects(api.getScan("scan"), (actual) => actual === error);
  await assert.rejects(api.getDiff("rem"), (actual) => actual === error);
});

test("facade reexports the transport's exact ApiError constructor", () => {
  assert.equal(ApiError, TransportError);
});

test("HTTP boundary preserves caller headers and request options", async () => {
  const signal = new AbortController().signal;
  await request("/custom", { method: "PATCH", body: "{}", headers: { Accept: "custom/json", "Content-Type": "custom/type" }, signal, credentials: "include" });
  assert.deepEqual(requests, [{ url: "/custom", method: "PATCH", accept: "custom/json", contentType: "custom/type", body: "{}" }]);
  assert.equal(calls[0].init.signal, signal);
  assert.equal(calls[0].init.credentials, "include");
});

test("HTTP boundary does not add JSON content type for a falsy body", async () => {
  await request("/custom", { method: "POST", body: "" });
  assert.deepEqual(calls[0].init.headers, { Accept: "application/json" });
  response.body = "plain text";
  assert.equal(await requestText("/custom"), "plain text");
  assert.equal(calls[1].init, undefined);
});

test("SBOM and watch URL builders retain their distinct encoding rules", () => {
  assert.equal(api.sbomURL("raw/name", "cyclonedx"), `${API_ROOT}/scans/raw/name/sbom?format=cyclonedx`);
  assert.equal(api.sbomURL("scan", "spdx"), `${API_ROOT}/scans/scan/sbom?format=spdx`);
  assert.equal(watchURL("scans"), `${API_ROOT}/scans?watch=true`);
  assert.equal(watchURL("scans", ""), `${API_ROOT}/scans?watch=true`);
  assert.equal(watchURL("scans", "a/b c&d"), `${API_ROOT}/scans?watch=true&fieldSelector=metadata.name%3Da%2Fb+c%26d`);
});

// Minimal React/SSE boundary harness: cache behavior still runs against the
// real QueryClient. Effects/dependencies come from the actual useWatch hook.
import { mock } from "node:test";
import { QueryClient } from "@tanstack/react-query";

let client;
let effect;
let dependencies;
let cleanup;
const sources = [];

mock.module("react", { exports: { useEffect(fn, deps) { effect = fn; dependencies = deps; } } });
mock.module("@tanstack/react-query", { exports: { useQueryClient: () => client } });
const { useWatch } = await import("../src/hooks/use-watch.ts");

class FakeEventSource {
  constructor(url) {
    this.url = url;
    this.closed = 0;
    sources.push(this);
  }
  emit(event) { this.onmessage({ data: JSON.stringify(event) }); }
  close() { this.closed++; }
}

export { QueryClient };

export function mountWatch(qc, resource, options = {}) {
  const original = globalThis.EventSource;
  globalThis.EventSource = FakeEventSource;
  client = qc;
  sources.length = 0;
  cleanup = undefined;
  let previousDeps;
  function render(nextResource = resource, nextOptions = options, nextClient = qc) {
    client = nextClient;
    useWatch(nextResource, nextOptions);
    if (!previousDeps || dependencies.some((dep, i) => !Object.is(dep, previousDeps[i]))) {
      cleanup?.();
      cleanup = effect();
      previousDeps = dependencies;
    }
  }
  render();
  return {
    sources,
    get source() { return sources.at(-1); },
    render,
    close() {
      cleanup?.();
      cleanup = undefined;
      globalThis.EventSource = original;
    },
  };
}

// Node handles erasable TypeScript; this hook only supplies the source alias
// and extension resolution that Vite normally provides. No test dependency.
import { existsSync } from "node:fs";
import { registerHooks } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const sourceRoot = new URL("../src/", import.meta.url);

registerHooks({
  resolve(specifier, context, nextResolve) {
    const local = specifier.startsWith("@/")
      ? new URL(specifier.slice(2), sourceRoot)
      : specifier.startsWith(".") && context.parentURL
        ? new URL(specifier, context.parentURL)
        : undefined;
    if (local?.protocol === "file:") {
      for (const suffix of ["", ".ts"]) {
        const path = fileURLToPath(local) + suffix;
        if (path.endsWith(".ts") && existsSync(path)) {
          return { url: pathToFileURL(path).href, shortCircuit: true };
        }
      }
    }
    return nextResolve(specifier, context);
  },
});

#!/usr/bin/env python3
"""Exercise a packaged CLI against explicit offline HTTP fixtures, not live data."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


class FixtureAPI(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, body, status=200):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/kev":
            self.send_json({"catalogVersion": "fixture", "vulnerabilities": []})
        elif self.path.startswith("/epss"):
            self.send_json({"data": []})
        elif self.path.startswith("/nvd"):
            self.send_json({"totalResults": 0, "startIndex": 0, "resultsPerPage": 0, "vulnerabilities": []})
        elif self.path == "/v1/vulns/GHSA-fixture":
            self.send_json({"id": "GHSA-fixture", "modified": "2026-01-01T00:00:00Z",
                            "summary": "Offline package-test fixture", "database_specific": {"severity": "HIGH"},
                            "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]})
        else:
            self.send_json({"error": "fixture route not found"}, 404)

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path != "/v1/querybatch":
            self.send_json({"error": "fixture route not found"}, 404)
            return
        self.send_json({"results": [{"vulns": [{"id": "GHSA-fixture", "modified": "2026-01-01T00:00:00Z"}]}
                                    for _ in request["queries"]]})


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sequence(value, field):
    if value is None:
        return []  # Go nil slices are valid JSON null; other empty shapes are not.
    require(isinstance(value, list), f"{field} must be an array or null")
    return value


def check_reports(directory, expected):
    documents = {}
    for filename in ["report.json", "results.sarif", "sbom.cyclonedx.json", "sbom.spdx.json"]:
        value = json.loads((directory / filename).read_text())
        require(isinstance(value, dict), f"{filename} must be an object")
        documents[filename] = value
    report, sarif = documents["report.json"], documents["results.sarif"]
    inventory, match = report["inventory"], report["match"]
    components = sequence(inventory["components"], "inventory.components")
    findings = sequence(match["findings"], "match.findings")
    warnings = sequence(match.get("warnings"), "match.warnings")
    require(all(isinstance(w, str) and w.strip() for w in warnings), "malformed scan warnings")
    complete = expected != 2
    require(bool(warnings) != complete, "fixture completeness disagrees with warnings")
    require(sarif["version"] == "2.1.0", "unexpected SARIF version")
    runs = sequence(sarif["runs"], "SARIF runs")
    require(len(runs) == 1, "fixture must produce one SARIF run")
    invocations = sequence(runs[0]["invocations"], "SARIF invocations")
    require(invocations and all(i.get("executionSuccessful") is complete for i in invocations),
            "SARIF completeness disagrees with the fixture")
    results = sequence(runs[0]["results"], "SARIF results")
    cdx, spdx = documents["sbom.cyclonedx.json"], documents["sbom.spdx.json"]
    require(cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.6", "unexpected CycloneDX format")
    require(spdx["spdxVersion"] == "SPDX-2.3", "unexpected SPDX version")
    cdx_components = sequence(cdx.get("components"), "CycloneDX components")
    spdx_packages = sequence(spdx["packages"], "SPDX packages")
    summary = (directory / "summary.md").read_text()
    require(bool(summary.strip()), "missing summary")
    if complete:
        require(bool(sequence(inventory["projects"], "inventory.projects")), "no fixture project was scanned")
        require(len(components) == 1 and components[0].get("name") == "requests"
                and components[0].get("version") == "2.19.1", "fixture dependency was not inventoried")
        require(len(findings) == 1 and findings[0].get("vulnerabilityID") == "GHSA-fixture"
                and findings[0].get("componentID") == components[0]["id"], "expected bound fixture finding")
        require(len(results) == 1 and results[0].get("ruleId") == "GHSA-fixture", "missing fixture SARIF result")
        require(any(c.get("name") == "requests" and c.get("version") == "2.19.1" for c in cdx_components),
                "missing CycloneDX fixture component")
        require(any(p.get("name") == "requests" and p.get("versionInfo") == "2.19.1" for p in spdx_packages),
                "missing SPDX fixture package")
        require("GHSA-fixture" in summary, "summary omitted the fixture finding")
    else:
        require(not components and not findings and not results, "incomplete input retained stale analysis")
        require(not any(c.get("name") == "requests" for c in cdx_components)
                and not any(p.get("name") == "requests" for p in spdx_packages), "SBOM retained stale dependency")


def input_snapshot(directory):
    """Record fixture entries without following any unexpected symlink."""
    snapshot = {}
    for entry in directory.rglob("*"):
        key = str(entry.relative_to(directory))
        if entry.is_symlink():
            snapshot[key] = ("symlink", os.readlink(entry))
        elif entry.is_file():
            snapshot[key] = ("file", entry.read_bytes())
        elif entry.is_dir():
            snapshot[key] = ("directory",)
        else:
            snapshot[key] = ("other", entry.lstat().st_mode)
    return snapshot


def main():
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureAPI)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="cassandra-package-test-", dir=os.environ.get("TMPDIR")) as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            manifest = source / "requirements.txt"
            manifest.write_text("requests==2.19.1\n")
            endpoint = f"http://127.0.0.1:{server.server_port}"
            args = [binary, "scan", "--path", str(source),
                    "--repository", "example/fixture", "--timeout", "15s", "--go-proxy", "",
                    "--osv-url", endpoint, "--kev-url", endpoint + "/kev",
                    "--nvd-url", endpoint + "/nvd", "--epss-url", endpoint + "/epss"]
            env = dict(os.environ)
            env.pop("NVD_API_KEY", None)
            env.pop("GITHUB_TOKEN", None)
            results = {}
            for name, extra, expected in [("policy-block", [], 1), ("gate-disabled", ["--fail-on", "none"], 0),
                                          ("incomplete-input", [], 2)]:
                if name == "incomplete-input":
                    manifest.write_text("???\n")
                output = root / ("reports-" + name)
                if output.exists():
                    raise AssertionError(f"{name}: output directory must be fresh")
                before = input_snapshot(source)
                run = subprocess.run(args + ["--output-dir", str(output)] + extra,
                                     env=env, text=True, capture_output=True, timeout=20)
                if input_snapshot(source) != before:
                    raise AssertionError(f"{name}: scanner changed its input")
                if run.returncode != expected:
                    raise AssertionError(f"{name}: expected {expected}, got {run.returncode}\n{run.stdout}\n{run.stderr}")
                results[name] = run.returncode
                check_reports(output, expected)
            print(json.dumps({"packaged_cli": binary, "offline_fixture_exit_codes": results}, indent=2))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()

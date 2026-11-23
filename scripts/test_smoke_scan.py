#!/usr/bin/env python3
"""Verifier regression tests with an explicitly synthetic executable.

These tests do not prove a real scan; release CI separately runs smoke_scan.py
against the packaged Cassandra binary and its local HTTP fixture.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SMOKE = Path(__file__).with_name("smoke_scan.py")
SYNTHETIC_CLI = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
source = pathlib.Path(args[args.index('--path') + 1])
out = pathlib.Path(args[args.index('--output-dir') + 1])
count_file = pathlib.Path(os.environ['SYNTHETIC_COUNT'])
count = int(count_file.read_text()) + 1 if count_file.exists() else 1
count_file.write_text(str(count))
with open(os.environ['SYNTHETIC_OUTPUTS'], 'a') as log:
    log.write(str(out) + '\n')
incomplete = (source / 'requirements.txt').read_text() == '???\n'
code = 2 if incomplete else (0 if '--fail-on' in args else 1)
mode = os.environ['SYNTHETIC_MODE']
if mode == 'first-only' and count > 1:
    sys.exit(code)
component = {'id': 'pkg:pypi/requests@2.19.1', 'name': 'requests', 'version': '2.19.1'}
findings = [] if incomplete else [{'componentID': component['id'], 'vulnerabilityID': 'GHSA-fixture'}]
components = [] if incomplete else [component]
report = {'inventory': {'projects': [{'id': 'fixture'}], 'components': components},
          'match': {'findings': findings, 'warnings': ['fixture incomplete'] if incomplete else []}}
sarif = {'version': '2.1.0', 'runs': [{'invocations': [{'executionSuccessful': not incomplete}],
         'results': [] if incomplete else [{'ruleId': 'GHSA-fixture'}]}]}
cdx = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': components}
spdx = {'spdxVersion': 'SPDX-2.3', 'packages': [] if incomplete else [{'name': 'requests', 'versionInfo': '2.19.1'}]}
out.mkdir(exist_ok=True)
for name, value in [('report.json', report), ('results.sarif', sarif),
                    ('sbom.cyclonedx.json', cdx), ('sbom.spdx.json', spdx)]:
    (out / name).write_text(json.dumps({} if mode == 'empty-json' else value))
(out / 'summary.md').write_text('Synthetic verifier fixture: GHSA-fixture\n')
if mode == 'mutate-first-input' and count == 1:
    (source / 'requirements.txt').write_text('changed by synthetic negative fixture\n')
sys.exit(code)
'''


class SmokeVerifierContract(unittest.TestCase):
    def run_fixture(self, mode):
        with tempfile.TemporaryDirectory(prefix="cassandra-smoke-contract-", dir=os.environ.get("TMPDIR")) as temporary:
            root = Path(temporary)
            cli = root / "synthetic-cli"
            cli.write_text(SYNTHETIC_CLI)
            cli.chmod(0o700)
            env = dict(os.environ, SYNTHETIC_MODE=mode, SYNTHETIC_COUNT=str(root / "count"),
                       SYNTHETIC_OUTPUTS=str(root / "outputs"))
            result = subprocess.run([sys.executable, "-B", str(SMOKE), str(cli)],
                                    env=env, capture_output=True, text=True, timeout=30)
            outputs = (root / "outputs").read_text().splitlines() if (root / "outputs").exists() else []
            return result, outputs

    def test_compliant_synthetic_reports_can_pass(self):
        result, _ = self.run_fixture("valid")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_scan_requires_newly_written_reports(self):
        result, outputs = self.run_fixture("first-only")
        self.assertNotEqual(result.returncode, 0, "stale earlier reports must not validate another scan")
        self.assertGreaterEqual(len(set(outputs)), 2)
        self.assertIn("report.json", result.stderr)

    def test_syntactically_valid_empty_json_is_not_a_scan(self):
        result, _ = self.run_fixture("empty-json")
        self.assertNotEqual(result.returncode, 0, "empty JSON objects must not count as valid reports")

    def test_input_mutation_in_an_earlier_case_is_detected(self):
        result, _ = self.run_fixture("mutate-first-input")
        self.assertNotEqual(result.returncode, 0, "later fixture replacement must not hide earlier input mutation")
        self.assertIn("scanner changed its input", result.stderr)


if __name__ == "__main__":
    unittest.main()

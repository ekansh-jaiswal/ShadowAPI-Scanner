# Shadow API Discovery & Vulnerability Scanner

## Description

This tool performs shadow API discovery by diffing web server access logs against OpenAPI 3.0 specifications to identify undocumented endpoints receiving production traffic. It executes rule-based vulnerability heuristics based on the OWASP API Security Top 10 (2023), including an active Broken Object Level Authorization (BOLA) probe that attempts unauthorized cross-user access against ownership-scoped endpoints to confirm vulnerabilities.

## Prerequisites and Installation

Requires Python 3.11+.

```bash
python3.11 -m venv .
source bin/activate
pip install -r requirements.txt
```

## Quick Start (Mock Environment)

Run the mock server in the background, then execute the scanner against the generated synthetic logs. The mock server process blocks the terminal and must be run separately.

Terminal 1:
```bash
python mock_env/mock_server.py
```

Terminal 2:
```bash
python scanner/cli.py \
    --log-file mock_env/access.log \
    --spec mock_env/openapi_spec.yaml \
    --mock-server-url http://localhost:8000 \
    --output report.html \
    --fail-on critical,high
```

## Flag Reference

| Flag | Description |
|---|---|
| `--log-file PATH` | Path to Nginx combined-format access log. |
| `--headers-log PATH` | Path to companion JSONL auth-headers log (default: same directory as `--log-file`, filename `access_headers.log`). |
| `--spec PATH` | Path to OpenAPI 3.0 YAML/JSON spec file. |
| `--mock-server-url URL` | Base URL of the test server for active BOLA probes (e.g. `http://localhost:8000`). Omit or pass empty string to skip active probing. |
| `--no-active-probes` | Disable all active network probes (overrides `--mock-server-url`). |
| `--output PATH` | Output path for the HTML report (default: `report.html`). |
| `--fail-on SEVERITIES` | Comma-separated list of severities that trigger a non-zero exit code for CI/CD gating. Options: `critical`, `high`, `medium`, `low`, `info`. Default: `critical,high`. |
| `--exclude-from-bola RESOURCES` | Comma-separated list of resource-name keywords to exclude from active BOLA probing (e.g. `product,category`). Adds to the built-in exclusion list without requiring source-code changes. |
| `--quiet`, `-q` | Suppress progress output; only print the final summary. |
| `--version` | Print the tool's version and exit immediately. |

## Scoring Model

The scanner calculates a 0-100 score for each endpoint by summing the weighted severity of all its findings, capped at 100. The weights are: `CRITICAL=40`, `HIGH=25`, `MEDIUM=10`, `LOW=5`, and `INFO=1`.

The summed score maps to a baseline risk band:
- `CRITICAL`: 75 - 100
- `HIGH`: 50 - 74
- `MEDIUM`: 25 - 49
- `LOW`: 1 - 24
- `NONE`: 0

However, there is a hard floor for critical vulnerabilities: if an endpoint has ANY finding with a `CRITICAL` severity, its overall risk level is forced to `CRITICAL` regardless of its summed score. An endpoint with a low numeric score will still show a `CRITICAL` badge if even one of its findings is of critical severity.

## Running Against a Real Target

In a production deployment, `--log-file` accepts standard Nginx or Apache combined access logs. The OpenAPI specification should be exported from the API gateway or developer portal.

WARNING: The `--mock-server-url` flag enables active BOLA probing, which makes authenticated network requests attempting unauthorized data access across user boundaries. Only point the active probe at systems you own or have explicit written authorization to test.

## Reading the Output

The CLI provides staged progress output indicating the status of log parsing, spec diffing, health checks, and risk evaluation.

The process returns one of the following exit codes:
- `0`: Scan completed; no findings met or exceeded the `--fail-on` threshold.
- `1`: Scan completed; at least one finding met or exceeded the `--fail-on` threshold (used for CI/CD gating).
- `2`: Usage error (e.g., input files like `--log-file` or `--spec` were not found).
- `3`: Unexpected runtime error or manual interruption during the scan.

The generated HTML report includes:
- A single Executive Summary section containing stat cards for the overall risk exposure (showing the aggregated gateway score and highest severity badge), total shadow endpoints, critical findings count, and total findings.
- An attack-surface table listing all discovered endpoints.
- Expandable finding cards containing HTTP evidence blocks (URLs, status codes, and response samples).
- DPDP Act 2023 overlay callouts highlighting provisions to review based on the OWASP finding category.
- A prominent warning banner if active probes were skipped due to the target server being unreachable.

## Validation Against OWASP crAPI

This scanner was validated against OWASP crAPI. Network traffic was captured and converted into the expected log format. The OpenAPI specification was supplied independently of the captured traffic. The scanner identified crAPI's Challenge 1 BOLA vulnerability on the `/identity/api/v2/vehicle/{id}/location` endpoint by structurally detecting the UUID and extracting cross-user token pairs from the log data.

The OpenAPI specification must come from an independent source rather than being auto-generated from the scanned traffic. If the spec is generated from the same traffic used for analysis, shadow APIs cannot be discovered, as undocumented endpoints would be absorbed into the baseline spec.

## Troubleshooting

- Mock server blocking: The mock server (`mock_env/mock_server.py`) is a blocking process. It must be run in a separate terminal or backgrounded before invoking `scanner/cli.py`.
- Unreachable mock server: If the scanner cannot reach the `--mock-server-url` during the initial health check, it will print a warning, skip active BOLA probes, and fall back to passive analysis.
- Line-count mismatch: The access log and headers log must maintain line-count parity. If lines are dropped or misaligned during capture, log parsing will fail.

## License

Licensed under the Apache-2.0 License. See the LICENSE file for details.

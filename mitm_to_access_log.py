#!/usr/bin/env python3
"""
Converts a real mitmproxy capture (.mitm flow file) into the Nginx
combined-log format and companion auth-headers JSONL format that
scanner/log_parser.py expects.

This script does NOT know in advance which endpoints were visited,
which requests matter, or which one is a vulnerability. It reads every
single flow in the capture file and writes a corresponding log line
for each one, in the order they actually happened. Whatever the
scanner finds when run against the resulting log is a genuine result
of the diff engine and risk engine processing real captured traffic,
not a pre-selected demonstration.

Usage:
    python mitm_to_access_log.py crapi_capture.mitm \
        --out-log crapi_access.log \
        --out-headers crapi_access_headers.log
"""
import argparse
import json
import sys
from datetime import datetime, timezone

try:
    from mitmproxy.io import FlowReader
except ImportError:
    print("mitmproxy not installed. Run: pip install mitmproxy --break-system-packages", file=sys.stderr)
    sys.exit(1)


def nginx_timestamp(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_file", help="Path to the .mitm flow file")
    parser.add_argument("--out-log", default="access.log")
    parser.add_argument("--out-headers", default="access_headers.log")
    args = parser.parse_args()

    count = 0
    skipped = 0

    with open(args.capture_file, "rb") as f, \
         open(args.out_log, "w") as log_f, \
         open(args.out_headers, "w") as hdr_f:

        reader = FlowReader(f)
        for flow in reader.stream():
            # Only process HTTP flows with a completed response
            if not hasattr(flow, "request") or flow.response is None:
                skipped += 1
                continue

            req = flow.request
            resp = flow.response

            method = req.method
            path = req.path.split("?")[0]  # strip query string for the log path field
            status = resp.status_code
            size = len(resp.content) if resp.content else 0
            ua = req.headers.get("User-Agent", "-")
            source_ip = req.headers.get("X-Forwarded-For", "127.0.0.1")

            ts = nginx_timestamp(req.timestamp_start)
            log_line = (
                f'{source_ip} - - [{ts}] '
                f'"{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
            )
            log_f.write(log_line + "\n")

            auth_header = req.headers.get("Authorization")
            hdr_f.write(json.dumps({
                "timestamp": datetime.fromtimestamp(req.timestamp_start, tz=timezone.utc).isoformat(),
                "source_ip": source_ip,
                "method": method,
                "path": path,
                "status": status,
                "has_authorization": auth_header is not None,
                "token": auth_header if auth_header else None,
                "token_owner": None,  # unknown at capture time, not inferred here
                "user_agent": ua,
            }) + "\n")

            count += 1

    print(f"Processed capture: {args.capture_file}")
    print(f"  {count} HTTP request/response pairs written")
    print(f"  {skipped} incomplete/non-HTTP flows skipped")
    print(f"Output: {args.out_log}, {args.out_headers}")


if __name__ == "__main__":
    main()
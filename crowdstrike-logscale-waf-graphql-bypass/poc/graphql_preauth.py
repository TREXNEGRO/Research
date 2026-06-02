#!/usr/bin/env python3
"""
graphql_preauth.py — LogScale GraphQL pre-auth reachability probe.

Sends four queries against /graphql on a LogScale lightweight-ingest
host and prints which root fields resolve without authentication.
The intended use is a defender smoke test: confirm whether your
perimeter is exposing the GraphQL endpoint at all, and if so, whether
`meta` and `installedLicense` are reachable pre-auth on your build.

Queries sent (in order, 3 s apart):
    1. { __typename }                          — schema reachability
    2. { meta { __typename version
                clusterId environment } }      — pre-auth metadata leak
    3. { installedLicense { __typename } }     — license object reach
    4. { viewer { username } }                 — guard-rail check
                                                 (expected: 401 / auth-required)

NOTE: this script intentionally STOPS at `OnPremLicense { __typename }`.
It does NOT enumerate License sub-fields (`issuer`, `organization`,
`contactEmail`, `contractId`, etc.) because those may contain
customer-identifying data. If you are running this against your own
LogScale, you can add a fifth query; if you are running it under a
bounty program, do not.

Usage:
    python3 graphql_preauth.py https://target.example.com

License: MIT.
"""

from __future__ import annotations
import json
import sys
import time
import urllib.error
import urllib.request


QUERIES: list[tuple[str, str]] = [
    ("1. schema reachability",
     "{__typename}"),
    ("2. meta (pre-auth metadata)",
     "{ meta { __typename version clusterId environment } }"),
    ("3. installedLicense (typename only)",
     "{ installedLicense { __typename } }"),
    ("4. viewer (expected: auth challenge)",
     "{ viewer { username } }"),
]

HEADERS = {
    "X-Research-Probe": "defender-checklist",
    "User-Agent":       "cve-2026-40050-checker/1.0",
    "Content-Type":     "application/json",
}

DELAY_SECONDS = 3


def post_graphql(base: str, query: str) -> tuple[int, dict]:
    url = base.rstrip("/") + "/graphql"
    body = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"_raw": raw[:300]}
    except Exception as e:  # noqa: BLE001
        return -1, {"_error": repr(e)}


def summarise(label: str, status: int, payload: dict) -> str:
    if status == -1:
        return f"  request error: {payload.get('_error')}"

    errors = payload.get("errors") or []
    if errors:
        msg = errors[0].get("message", "?")
        if "Authorization Required" in msg:
            return f"  status={status} — AUTH REQUIRED (expected: guarded field)"
        return f"  status={status} — error: {msg}"

    data = payload.get("data") or {}
    if not data:
        return f"  status={status} — empty data, payload={payload}"

    # Surface a few interesting facts if present.
    interesting = []
    if "meta" in data and isinstance(data["meta"], dict):
        m = data["meta"]
        for k in ("version", "clusterId", "environment", "__typename"):
            if k in m:
                interesting.append(f"meta.{k}={m[k]!r}")
    if "installedLicense" in data and isinstance(data["installedLicense"], dict):
        for k, v in data["installedLicense"].items():
            interesting.append(f"installedLicense.{k}={v!r}")
    if "__typename" in data and not isinstance(data.get("__typename"), dict):
        interesting.append(f"__typename={data['__typename']!r}")
    if not interesting:
        interesting = [f"data={json.dumps(data)[:200]}"]

    head = f"  status={status} — RESOLVED PRE-AUTH"
    return head + "\n    " + "\n    ".join(interesting)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <target-base-url>", file=sys.stderr)
        return 2
    base = argv[1].rstrip("/")
    if not base.startswith(("http://", "https://")):
        print("error: target must be a full URL with scheme", file=sys.stderr)
        return 2

    print(f"# target  : {base}/graphql")
    print(f"# header  : {dict((k, v) for k, v in HEADERS.items() if k != 'Content-Type')}")
    print(f"# delay   : {DELAY_SECONDS}s between requests")
    print(f"# stop-on : OnPremLicense.__typename (NO sub-field enumeration)")
    print()

    for label, query in QUERIES:
        print(label)
        print(f"  query : {query}")
        status, payload = post_graphql(base, query)
        print(summarise(label, status, payload))
        print()
        time.sleep(DELAY_SECONDS)

    print("# done.")
    print("# expected good outcome: query 4 returns 'Authorization Required'.")
    print("# expected bad  outcome: queries 2 and 3 return RESOLVED PRE-AUTH,")
    print("# which is the CVE-2026-40050 routing-tree exposure surfacing through")
    print("# the GraphQL endpoint. If both queries pre-auth-resolve, your build")
    print("# is on a 1.234.x routing tree and the WAF does not cover /graphql.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

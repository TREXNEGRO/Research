# crowdstrike-logscale-waf-graphql-bypass

Reproducer and evidence for the CrowdStrike LogScale CVE-2026-40050
mitigation bypass and the adjacent pre-auth GraphQL exposure on the
same SaaS hosts. Companion write-up:

**[trexnegro.github.io/posts/crowdstrike-logscale-waf-bypass-graphql-preauth/](https://trexnegro.github.io/posts/crowdstrike-logscale-waf-bypass-graphql-preauth/)**

The vendor declined the underlying bounty report; this entry is the
public research note for defenders running LogScale on their own
perimeter.

## The two findings, in one paragraph

CVE-2026-40050 is a routing-tree exposure on LogScale lightweight-ingest
nodes. The advisory lists 1.224.0–1.234.0 as vulnerable and credits the
SaaS fleet as "patched" because a perimeter WAF rule was deployed in
April 2026. That rule drops `/api/v1/internal/*` with a 403 at the nginx
tier. The rule fails on URL-decoded match — `GET /api/v1/%69nternal/status`
returns 200 with the backend's JSON banner (eleven equivalent path
permutations all bypass the same rule). The same hosts also serve
`/graphql`, which the rule never covered, and the GraphQL `Query.meta`
and `Query.installedLicense` root fields resolve pre-auth, leaking
cluster id, environment (`ON_CLOUD`), version SHA, and the License
object typename. A JAR-level diff of `context-implementation.jar`
between v1.234.1 (first advisory-listed "patched" version) and v1.235.1
(actual code-level fix) shows the SaaS fleet on 1.234.x is sitting on
the WAF, not on the code fix — the routing tree is byte-identical to
the vulnerable code, only the perimeter changed.

## What's in here

```
crowdstrike-logscale-waf-graphql-bypass/
├── README.md                 — this file
├── poc/
│   ├── encoding_variants.py  — walks all 11 path-encoding variants;
│   │                            prints which ones the WAF blocks and
│   │                            which the backend serves. Useful as
│   │                            a regression test against any
│   │                            path-matching WAF, not just this one.
│   └── graphql_preauth.py    — sends four GraphQL queries against
│                                a host URL passed on the command line.
│                                Stops at `OnPremLicense { __typename }`;
│                                does NOT enumerate License sub-fields.
└── evidence/
    ├── curl-output.txt       — raw curl -isS output from the 2026-06-01
    │                            run, with timestamps.
    └── jar-diff-notes.md     — strings + javap output from the
                                 v1.234.1 vs v1.235.1 context-implementation.jar
                                 comparison, focused on Routing and
                                 LightweightIngestOnlyUriFilter.
```

## How to run

```bash
# 1) WAF bypass — sends all 11 path-encoding permutations
python3 poc/encoding_variants.py https://ingest.oem-2-1.logscale.us-2.crowdstrike.com

# 2) GraphQL pre-auth probe — meta + installedLicense typename
python3 poc/graphql_preauth.py https://ingest.oem-2-1.logscale.us-2.crowdstrike.com
```

Both scripts default to a **3 s inter-request delay** and set an
identifying `X-Research-Probe` header on every request so a defender
reviewing logs can see what hit them. Run only against hosts you own
or have explicit written permission to test.

## Why this is here and not in a CVE bump

The vendor's read of the advisory range (`1.224.0 ≤ version ≤ 1.234.0`)
is consistent with the version banner the affected SaaS hosts return
(`1.234.3`, above the range), so the bounty triager closed the report as
not meeting the program's bar. The argument in the write-up is that the
advisory's "patched" semantics for 1.234.1–1.234.3 is the WAF — not a
code fix — and the WAF is bypassable; the version string alone is not
the patch status. I disagree with the close, but a closed bounty
report is closed. Publishing the technical content gives defenders
running their own LogScale instances the receipts to decide for
themselves whether their perimeter is doing the work the version
banner implies.

## Mitigation for defenders

1. **Upgrade to 1.235.1 or later.** That release adds
   `LightweightIngestOnlyUriFilter`, which enforces the allowlist
   at the code level — the routing tree exposure is genuinely closed
   and the WAF becomes belt-and-braces rather than the only defence.
2. If an immediate upgrade is infeasible:
   - Make sure your perimeter URL-decodes before matching. Path-string
     WAF rules without decode-then-match cannot defend a backend that
     decodes-then-routes.
   - Cover `/graphql` explicitly. It's part of the CVE scope; it is
     not covered by the SaaS-side WAF rule as deployed.
   - Audit per-field auth on the GraphQL schema. `meta` and
     `installedLicense` were observed pre-auth on 1.234.3; assume more
     fields share that exposure until you've enumerated.
3. Re-verify with the smoke test in `poc/encoding_variants.py` and
   `poc/graphql_preauth.py` against each in-scope host before marking
   the CVE remediated for that tenant.

## License

MIT. Reproducer code only — no exploitation primitives beyond the
request-and-response shapes documented in the public write-up.

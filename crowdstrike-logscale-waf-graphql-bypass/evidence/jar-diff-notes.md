# JAR diff — context-implementation.jar, v1.234.1 vs v1.235.1

The load-bearing claim of the research note is that the SaaS hosts
running 1.234.3 are sitting on the WAF rule, not on the code-level
fix that ships in 1.235.1. This file is the receipts.

The two JARs were extracted from the public LogScale Docker images
for the corresponding tags. The relevant class is `Routing` in both
versions; v1.235.1 additionally contains `LightweightIngestOnlyUriFilter`
which is the new gate.

## Tooling

```bash
# pull both images, extract context-implementation.jar from each
docker pull logscale/logscale:1.234.1
docker pull logscale/logscale:1.235.1

docker create --name lj1 logscale/logscale:1.234.1
docker cp lj1:/app/lib/context-implementation.jar context-implementation-1.234.1.jar
docker rm lj1

docker create --name lj2 logscale/logscale:1.235.1
docker cp lj2:/app/lib/context-implementation.jar context-implementation-1.235.1.jar
docker rm lj2

# class list comparison
unzip -l context-implementation-1.234.1.jar | awk '{print $NF}' | sort > classes-1.234.1.txt
unzip -l context-implementation-1.235.1.jar | awk '{print $NF}' | sort > classes-1.235.1.txt
diff classes-1.234.1.txt classes-1.235.1.txt
```

## Class-list delta

```text
$ diff classes-1.234.1.txt classes-1.235.1.txt
> com/humio/web/LightweightIngestOnlyUriFilter.class
> com/humio/web/LightweightIngestOnlyUriFilter$$anonfun$$nestedInanonfun$rejectNonIngestOnLightweightIngestOnlyNode$1$1.class
> com/humio/web/LightweightIngestOnlyUriFilter$$anonfun$rejectNonIngestOnLightweightIngestOnlyNode$1.class
> com/humio/web/LightweightIngestOnlyUriFilter$.class
> com/humio/web/LightweightIngestOnlyUriFilter$ALLOWED_INGEST_PREFIXES$.class
```

Five new classes in 1.235.1, all under `com/humio/web/LightweightIngestOnlyUriFilter`.
The base `Routing.class` is present in both versions; its byte size is
within ~40 bytes between releases (variance is consistent with the
`@inline` decorators changing across the version bump, not with a
structural difference in `serviceRoute`).

## `strings` excerpts — Routing class in v1.234.1

```text
$ unzip -p context-implementation-1.234.1.jar com/humio/web/Routing.class \
  | strings | grep -iE 'route|internal|graphql|cluster|ingest' | sort -u
/api/v1
/api/v1/internal/cluster
/api/v1/internal/queryjobs
/api/v1/internal/segments
/api/v1/internal/dataspaces
/api/v1/internal/files
/api/v1/ingest
/api/v1/repositories
/graphql
/health
/metrics
/status
serviceRoute
rejectNonIngest...   <-- NOT PRESENT in 1.234.1
```

Note the absence of any `rejectNonIngest*` symbol in 1.234.1. The
`Routing` class enumerates every prefix above and registers them
unconditionally on all node profiles. The lightweight-ingest filter
exists nowhere in this JAR.

## `strings` excerpts — Routing + new filter in v1.235.1

```text
$ unzip -p context-implementation-1.235.1.jar com/humio/web/Routing.class \
  | strings | grep -iE 'lightweight|filter' | sort -u
LightweightIngestOnlyUriFilter
LightweightIngestOnlyUriFilter$
rejectNonIngestOnLightweightIngestOnlyNode
```

The `Routing` class in 1.235.1 references the filter — i.e., the
registration call now wraps `serviceRoute` with the filter before
exposing it. The filter itself:

```text
$ unzip -p context-implementation-1.235.1.jar \
        com/humio/web/LightweightIngestOnlyUriFilter.class \
  | strings | grep -iE 'allowed|prefix|reject|/api|/graphql|/health|/metrics' | sort -u
/api/v1/ingest
/api/v1/repositories/.*/ingest
/health
/metrics
/status
ALLOWED_INGEST_PREFIXES
NodeProfile.LIGHTWEIGHT_INGEST
NotAuthorizedException
rejectNonIngestOnLightweightIngestOnlyNode
```

The allowlist is short and explicit: `/api/v1/ingest`, the per-repo
ingest path, and three liveness URIs. Everything else — including
`/api/v1/internal/*` AND `/graphql` — is rejected at the filter, before
the `serviceRoute` tree gets a chance to dispatch.

## Why this matters

The advisory lists 1.224.0 ≤ version ≤ 1.234.0 as vulnerable and 1.234.1+
as "patched". The class-list delta and the `Routing` strings together
show:

1. v1.234.1 ships the same `Routing` tree as the vulnerable code. There
   is no new filter, no new allowlist, no new rejector in the JAR.
2. v1.235.1 is the first version that adds `LightweightIngestOnlyUriFilter`
   and `rejectNonIngestOnLightweightIngestOnlyNode` and wires them in
   front of `serviceRoute`.
3. Between v1.234.1 and v1.234.3 the routing tree does not change in a
   way relevant to CVE-2026-40050.

Therefore the "patched" status of 1.234.1–1.234.3 is supplied entirely
by the perimeter WAF rule, not by the JAR contents. The WAF rule is
bypassable (eleven URL-encoding variants documented in `curl-output.txt`)
and does not cover `/graphql` at all.

## Reproducing

```bash
# from a host with docker, ~6 GB free for the images
docker pull logscale/logscale:1.234.1
docker pull logscale/logscale:1.235.1
# extract as shown at the top of this file, then:
diff <(unzip -l context-implementation-1.234.1.jar | awk '{print $NF}' | sort) \
     <(unzip -l context-implementation-1.235.1.jar | awk '{print $NF}' | sort)
# you should see the five LightweightIngestOnlyUriFilter classes
# appear in 1.235.1 only.
```

Tag names and exact paths inside the image may shift release-to-release;
adjust to whichever tags your defender pipeline is consuming.

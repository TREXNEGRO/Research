# PDFWKRNL.sys — sample-by-sample HVCI status

**Last checked**: 2026-06-03 against MS HVCI vulnerable-driver block list (`aka.ms/VulnerableDriverBlockList`, May 12 2026 build).

**Source**: loldrivers.io has 5 known-vulnerable samples of PDFWKRNL.sys. MS block list lists 5 hashes. Cross-reference:

| # | SHA256 of file | Authentihash SHA1 | MS-blocked? | Notes |
|---|---|---|---|---|
| 1 | `6e8b49cf70bf854e8c59c7d27cefa89406caf8978461190dabb86dafcd8554e1` | `661a1a28950cec3f2c3d0e72ab2a05d4a173cf9a` | **NO** | Created on loldrivers 2026-03-20 (ESET EDR-killers article). Shares Authentihash with #4. |
| 2 | `0cf84400c09582ee2911a5b1582332c992d1cd29fcf811cb1dc00fcd61757db0` | `6370c82c2dbdf93608cccb88d78468edeb27f5d08f9ed0baf161842c0751f6a4` (SHA256) | **YES** | VMware CB hunt article Nov 2023. Blocked by both file SHA256 AND Authentihash. |
| 3 | `5df689a62003d26df4aefbaed41ec1205abbf3a2e18e1f1d51b97711e8fcdf00` | `cd5bff03256b98922b47a2725128540953a0ac15bd2be204196917d0c707a9cb` (SHA256) | **NO** | v1.1 of the driver. Unique Authentihash. |
| 4 | `6945077a6846af3e4e2f6a2f533702f57e993c5b156b6965a552d6a5d63b7402` | `661a1a28950cec3f2c3d0e72ab2a05d4a173cf9a` | **NO** | **TARGET** — the sample referenced by g3tsyst3m article. Shares Authentihash with #1. |
| 5 | `f190919f1668652249fa23d8c0455acbde9d344089fde96566239b1a18b91da2` | `531ae2d8f7aa301b74a37b82b5f3cadbf91962e0` | **YES** | Listed as `ID_DENY_PDFWKKRNL_1` and `_4`. |

## What MS actually blocks (5 hash entries)

```
ID_DENY_PDFWKKRNL_1  Hash=531AE2D8F7AA301B74A37B82B5F3CADBF91962E0  (Authentihash SHA1 of #5)
ID_DENY_PDFWKKRNL_2  Hash=57612842EFBCA98673E68CDBE0461D341379BFC8  (other sample, not in loldrivers)
ID_DENY_PDFWKKRNL_3  Hash=2B29B91F9F63B65E8F0EC30442A89C9304B9EEFA
ID_DENY_PDFWKKRNL_4  Hash=F501DD79E0B49AB76BD8D43A79DA292C5224FA2B
ID_DENY_PDFWKKRNL_5  Hash=6370C82C2DBDF93608CCCB88D78468EDEB27F5D08F9ED0BAF161842C0751F6A4  (Authentihash SHA256 of #2)
```

`661a1a28950cec3f2c3d0e72ab2a05d4a173cf9a` (Authentihash of #1 + #4) is **not in this list** — confirming the article's claim.

## Picking the target sample

**Use Sample #4** (SHA256 `6945077a...`).

Rationale:
- Article-referenced and field-validated by g3tsyst3m
- Authentihash NOT in MS HVCI block list as of May 2026
- AMD-signed (USB-C Power Delivery Firmware Update Utility Driver), still has a valid kernel-mode signature

**Backup**: if Sample #4 gets blocklisted in a future MS update:
- Sample #3 (different Authentihash, same vulnerability) — fastest pivot
- Sample #1 (shares Authentihash with #4 — would be blocked together, so not a real backup)

## Operational caveats

1. **HVCI may still be more strict than VBS list**. The published block list is the user-mode AppLocker-style policy that gets applied to non-HVCI machines via the WindowsDriverDistribution-style scheduled task. Strict HVCI environments can block additional drivers via their own policies.
2. **AV may detect by file hash regardless of HVCI**. Defender ATP / Cortex XDR may flag the PE on disk based on community threat intel (loldrivers is a public source). Sample #4 SHA256 is publicly attributed as a known-vulnerable AMD driver.
3. **Mitigation pivot**: if disk-write of `PDFWKRNL.sys` is flagged, the chain can pivot to:
   - Service-manager-based load with renamed file (defeats name-based detection)
   - Reflective/in-memory driver loading via separate primitive (out of scope here)

## Cross-reference

- loldrivers: `https://www.loldrivers.io/drivers/ed27c0b8-6177-4132-a7af-5c15bcb386f3` (sample 1)
- loldrivers: `https://www.loldrivers.io/drivers/fded7e63-0470-40fe-97ed-aa83fd027bad` (samples 2-5)
- ESET research: https://www.welivesecurity.com/en/eset-research/edr-killers-explained/
- VMware Carbon Black: https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html
- g3tsyst3m: https://g3tsyst3m.com/byovd/BYOVD-and-Looting-LSASS-in-the-Modern-EDR-Era/

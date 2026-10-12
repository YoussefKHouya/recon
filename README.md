# Quality Recon

An ordered, modular reconnaissance pipeline for authorized bug-bounty, VDP, lab, and security-assessment work.

The pipeline preserves each tool's output separately, builds normalized canonical datasets, and measures overlap and unique contribution with ReconCompare plus a deterministic local report. Tools can be removed or reordered from one configuration section instead of rewriting the orchestration logic.

## Pipeline

The default dependency-aware order is:

```text
1. Subdomain enumeration
   ├── Subfinder
   ├── Assetfinder
   ├── Findomain
   ├── BBOT
   └── Osmedeus

2. Source comparison
   ├── ReconCompare
   └── Local overlap/unique-contribution report

3. DNS resolution
   ├── PureDNS
   └── DNSX fallback

4. Responsive HTTP services
   └── HTTPX

5. Stack and framework extraction
   └── Parsed from validated HTTPX JSONL

6. Historical URL collection
   ├── GAU
   ├── Waybackurls
   └── Waymore

7. Live crawling
   └── Katana against responsive URLs

8. URL and API analysis
   ├── API endpoints
   ├── JavaScript files
   ├── Authentication routes
   ├── Upload/download routes
   ├── Administration routes
   ├── OpenAPI/Swagger routes
   └── Parameterized URLs

9. Cloud enumeration
   ├── BBOT cloud modules
   └── Kaeferjaeger

10. Optional depth
    ├── Naabu
    └── Nuclei
```

DNS and alive checks intentionally precede Katana. Historical collectors can query the root independently, but a live crawler needs responsive URLs.

## Requirements

Runtime requirements:

- Bash 4+
- Python 3
- `setsid` from util-linux

The bundled `resolver.txt` is a snapshot of the MassDNS public resolver list and is used automatically by PureDNS. Override it with `--resolvers FILE` when needed.

Default external tools:

- Subfinder
- Assetfinder
- Findomain
- BBOT
- Osmedeus
- PureDNS or DNSX
- HTTPX
- GAU
- Waybackurls
- Waymore
- Katana
- ReconCompare
- Kaeferjaeger, expected at `~/kaeferjaeger.gay` unless `KAEFERJAEGER_DIR` is set

Optional deep stages:

- Naabu
- Nuclei

Missing complementary enumerators are recorded and skipped. Missing tools required by a selected DNS, alive, crawl, port, or Nuclei stage produce a failed/partial run instead of silent success.

## Installation

```bash
git clone https://github.com/YoussefKHouya/recon.git
cd recon
chmod +x recon.sh
```

Optional user-local installation:

```bash
install -m 0755 recon.sh "$HOME/.local/bin/quality-recon"
```

## Usage

> **Authorization:** the default pipeline performs active DNS resolution, HTTP probing, crawling, and cloud checks. Run it only against assets you own or are explicitly authorized to assess. Use `--dry-run` to inspect the plan without network execution.

Run the default ordered pipeline:

```bash
./recon.sh --domain example.com
```

Process a domain list:

```bash
./recon.sh --list domains.txt
```

Blank lines and lines beginning with `#` are ignored. Inline comments are supported:

```text
example.com
example.org # customer environment
```

Preview commands and artifacts without executing network tools:

```bash
./recon.sh --domain example.com --dry-run
```

Append bounded Naabu and Nuclei stages:

```bash
./recon.sh --domain example.com --deep
```

Display every option:

```bash
./recon.sh --help
```

## Tool and stage control

The control lists are centralized near the top of `recon.sh`:

```bash
STAGES_CSV="subdomains,compare,dns,alive,stack,archives,crawl,url-analysis,cloud"
SUBDOMAIN_TOOLS_CSV="subfinder,assetfinder,findomain,bbot,osmedeus"
ARCHIVE_TOOLS_CSV="gau,waybackurls,waymore"
CLOUD_TOOLS_CSV="bbot-cloud,kaeferjaeger"
```

They can also be overridden per run.

Remove redundant subdomain tools:

```bash
./recon.sh --domain example.com \
  --subdomain-tools subfinder,bbot,osmedeus
```

Run only passive enumeration and comparison:

```bash
./recon.sh --domain example.com \
  --stages subdomains,compare \
  --subdomain-tools subfinder,assetfinder,findomain,bbot
```

Run archive collection and URL classification only:

```bash
./recon.sh --domain example.com \
  --stages archives,url-analysis \
  --archive-tools gau,waybackurls,waymore
```

Select the cloud collectors explicitly:

```bash
./recon.sh --domain example.com \
  --stages cloud \
  --cloud-tools bbot-cloud,kaeferjaeger
```

Unknown tools, unknown stages, duplicates, and invalid dependency ordering fail before target output is created.

To add a new external tool:

1. Add its name to the relevant control list.
2. Add one Bash-array command builder.
3. Add one dispatch entry to the relevant stage.

Commands are executed as arrays and are never passed through `eval`.

## Rate controls

```bash
./recon.sh --domain example.com \
  --rate 5 \
  --dns-rate 100 \
  --port-rate 100 \
  --crawl-depth 2
```

| Option | Purpose | Accepted range |
|---|---|---:|
| `--rate` | Per-tool HTTP request ceiling where supported | 1–10 |
| `--dns-rate` | DNS query rate where supported | 1–500 |
| `--port-rate` | Naabu packets per second | 1–1000 |
| `--crawl-depth` | Katana crawl depth | 1–3 |

These are per-tool controls, not one global aggregate limit. Assetfinder, Findomain, archive providers, and Osmedeus do not expose one uniform hard RPS control; their concurrency is kept low or Osmedeus uses its `gently` preset.

The bundled `resolver.txt` is used by default. Supply another PureDNS resolver file with:

```bash
./recon.sh --domain example.com --resolvers resolvers.txt
```

## ReconCompare and redundancy analysis

Every selected subdomain enumerator writes separate evidence under:

```text
outputs/subdomains/raw/
outputs/subdomains/scoped/
```

Raw output is retained for provenance. Scoped files are normalized and restricted to the target root before comparison and merging.

Comparison output:

```text
outputs/compare/report.json
outputs/compare/report.txt
outputs/compare/reconcompare.json
outputs/compare/reconcompare.txt
```

The local report records:

- total union size;
- findings per tool;
- unique contribution;
- overlap with other tools;
- redundancy percentage;
- coverage percentage of the union;
- pairwise containment.

A tool producing zero unique results on one target is not removed automatically. Compare representative runs before deciding that it is redundant.

## Output layout

Each live execution gets an exclusive immutable run directory:

```text
~/Recon/<domain>/
├── runs/
│   └── <run-id>/
│       ├── completed.json
│       ├── logs/
│       │   ├── commands.log
│       │   ├── status.tsv
│       │   └── *.stdout.log / *.stderr.log
│       └── outputs/
│           ├── subdomains/
│           │   ├── raw/
│           │   ├── scoped/
│           │   └── all.txt
│           ├── compare/
│           ├── dns/
│           ├── http/
│           ├── stack/
│           ├── urls/
│           │   ├── raw/
│           │   └── classified/
│           ├── crawl/
│           ├── cloud/
│           ├── ports/
│           ├── nuclei/
│           ├── summary.json
│           └── summary.txt
└── latest -> runs/<run-id>
```

Dry runs are written to:

```text
~/Recon/<domain>/dry-run/
```

A dry run never replaces `latest`.

## Failure behavior

- One complementary tool failure does not stop independent tools.
- Required stage failures produce a partial run and a nonzero exit.
- PureDNS automatically falls back to DNSX when it fails or returns no resolved hosts.
- Malformed HTTPX JSONL fails the parser contract and cannot feed crawling or stack analysis.
- ReconCompare degradation does not destroy the deterministic local comparison report.
- `SIGINT` and `SIGTERM` give the active process group a short graceful shutdown window, then force termination if required.
- An interruption before atomic publication does not replace `latest`; a signal after publication leaves the already completed run intact.
- Captured logs and published text artifacts are redacted against configured and environment-provided secret values before publication.

Exit behavior:

| Code | Meaning |
|---:|---|
| `0` | Selected pipeline completed without recorded failures |
| `1` | Invalid configuration or preflight failure |
| `2` | Partial run with one or more failed stages/tools |
| `3` | No external reconnaissance tool completed successfully |
| `130` | Interrupted with SIGINT |
| `143` | Interrupted with SIGTERM |

## Verification

Run the synthetic suite without contacting real targets:

```bash
bash -n recon.sh
bash -n tests/test_recon.sh
bash tests/test_recon.sh
git diff --check
```

The suite uses fake binaries and covers command construction, stage ordering, output normalization, ReconCompare inputs, DNS fallback, malformed HTTPX output, secret redaction, failed tools, dry-run isolation, and process interruption.

## Responsible use

Use this project only on assets you own or are authorized to assess. The pipeline preserves evidence and applies bounded defaults, but it does not infer authorization or program policy.

Scanner output, public metadata, technology fingerprints, cloud candidates, and URL classifications are investigative leads—not confirmed vulnerabilities.

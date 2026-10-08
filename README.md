# Recon

A bounded, provenance-preserving reconnaissance pipeline for authorized bug-bounty and security testing.

`recon.sh` accepts one root domain or a newline-delimited domain list and writes reproducible artifacts under `~/Recon/<domain>/outputs/`. It keeps raw tool output, normalized results, stderr, and command provenance separate so findings can be traced back to their source.

## Features

- `passive`, `standard`, and `deep` profiles
- Single-domain and batch input
- Explicit scope acknowledgement for active profiles
- Unified HTTP rate control with a hard maximum of 10 requests per second per stage
- Raw and normalized output retained per tool
- Resume-safe and atomic artifact publication
- Unlimited stage runtime by default; optional operator-defined deadline
- Automatic BBOT and Kaeferjaeger cloud discovery in `standard` and `deep`
- Optional OneForAll, Osmedeus, Karma, and ReconCompare integration
- Narrow port discovery and targeted Nuclei validation in `deep`
- Secret redaction from captured output and persistent logs

## Requirements

The script uses available tools and skips missing optional components. Install the tools needed for your selected profile.

### Core

- Bash 4+
- Python 3
- GNU `timeout` only when `--max-time` is used
- Subfinder
- GAU

### Standard

- PureDNS or DNSX
- HTTPX
- Katana
- BBOT
- Kaeferjaeger checkout at `~/kaeferjaeger.gay`

### Deep and optional modules

- Naabu
- Nuclei
- OneForAll
- Osmedeus
- Waymore
- ReconCompare
- `karma-v2-safe`

## Installation

```bash
git clone https://github.com/YoussefKHouya/recon.git
cd recon
chmod +x recon.sh
```

Optional system-wide installation:

```bash
install -m 0755 recon.sh "$HOME/.local/bin/quality-recon"
```

## Usage

Passive discovery:

```bash
./recon.sh --domain example.com
```

Standard profile with active scope confirmation:

```bash
./recon.sh \
  --domain example.com \
  --profile standard \
  --ack-scope
```

Deep profile with the default 10-request-per-second ceiling:

```bash
./recon.sh \
  --domain example.com \
  --profile deep \
  --ack-scope \
  --rate 10
```

Process a domain list:

```bash
./recon.sh \
  --list domains.txt \
  --profile standard \
  --ack-scope \
  --resume
```

Preview commands and output layout without executing network tools:

```bash
./recon.sh --domain example.com --profile deep --ack-scope --dry-run
```

Display every option:

```bash
./recon.sh --help
```

## Profiles

| Profile | Behavior |
|---|---|
| `passive` | Passive subdomain and archive collection only |
| `standard` | Passive collection, DNS validation, HTTP inventory, crawling, BBOT, and Kaeferjaeger |
| `deep` | Standard profile plus optional DNS brute force, narrow port discovery, and targeted Nuclei validation |

`standard` and `deep` perform active requests and therefore require `--ack-scope`.

## Rate limits

`--rate N` controls HTTPX, Katana, BBOT, Nuclei, and active Karma stages. Accepted values are `1` through `10`; the default is `10`.

```bash
./recon.sh \
  --domain example.com \
  --profile deep \
  --ack-scope \
  --rate 10 \
  --crawl-rate 3
```

The limit applies independently to each stage, not as a shared host-wide aggregate. Naabu uses the separate `--port-rate` packet limit.

## Runtime

Stages have no wall-clock deadline by default. Slow collectors such as Amass, BBOT, Karma, and Osmedeus may run until they complete.

Set an explicit deadline only when you want one:

```bash
./recon.sh --domain example.com --profile deep --ack-scope --max-time 120
```

`--max-time 0` means unlimited and is the default. Accepted bounded values are 1 through 1440 minutes. Per-request network timeouts remain enabled so one dead connection cannot stall a scanner forever.

To watch the current run's logs from another terminal:

```bash
tail -n 30 -F ~/Recon/example.com/logs/*.log
```

The default terminal output reports:

- target, profile, effective rate, runtime policy, and output path;
- when each stage starts, completes, fails, or is skipped by `--resume`;
- stage duration and number of emitted items;
- a short stderr excerpt when a stage fails;
- final totals for subdomains, resolved hosts, web services, URLs, ports, and Nuclei leads;
- per-source subdomain counts and paths to the complete logs and machine-readable summary.

Tool output is live by default, but progress bars, counters, spinners, and duplicate status lines are filtered from the terminal. The unfiltered output remains in the stage log files. Useful diagnostics from core tools are shown as they happen; Osmedeus, Karma, BBOT, Kaeferjaeger, and OneForAll stream meaningful normal output and errors. Every executed command is printed with a `[>]` prefix. Completed text-producing stages show the result count, result path, and up to five sample findings instead of dumping thousands of lines.

For summary-only output:

```bash
./recon.sh --domain example.com --quiet
```

## Output

```text
~/Recon/<domain>/
├── inputs/
├── logs/
│   ├── run.json
│   ├── commands.log
│   └── *.stderr.log
└── outputs/
    ├── subdomains/
    │   ├── raw/
    │   └── all.txt
    ├── dns/
    ├── http/
    ├── urls/
    ├── crawl/
    ├── ports/
    ├── nuclei/
    ├── cloud/
    ├── osmedeus/
    ├── compare/
    └── summary.json
```

Raw source files remain separate from merged output. Cloud associations, bucket names, ASN ranges, third-party CNAMEs, and historical SNI matches are leads—not proof of ownership, authorization, or vulnerability.

## OneForAll

Set `ONEFORALL_HOME` when OneForAll is not installed at `~/tools/OneForAll`:

```bash
ONEFORALL_HOME=/opt/OneForAll \
  ./recon.sh --domain example.com --oneforall --ack-scope
```

The script enforces passive OneForAll flags:

```text
--brute False --dns False --req False --takeover False
```

## Safety

Use this project only on assets you own or are explicitly authorized to test.

The script intentionally does not:

- infer authorization from branding, DNS relationships, cloud associations, or historical data;
- run SQLMap by default;
- fuzz passwords or perform credential stuffing;
- attempt broad 403 or rate-limit bypasses;
- recursively fuzz POST requests;
- scan every port by default;
- treat scanner matches as confirmed vulnerabilities.

Review the applicable program policy before running active profiles.
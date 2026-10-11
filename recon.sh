#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION="2.0.0"
OUTPUT_ROOT="${HOME}/Recon"
DOMAIN=""
LIST_FILE=""
RATE=5
DRY_RUN=0
ACK_SCOPE=0

usage() {
  cat <<'EOF'
quality-recon: simple private reconnaissance runner

Runs one fixed command sequence. Every command is printed, its live output is
shown, stdout/stderr are saved, and a full summary is generated at the end.

USAGE
  recon.sh --domain example.com --ack-scope
  recon.sh --list domains.txt --ack-scope

OPTIONS
  -d, --domain DOMAIN     One root domain
  -l, --list FILE         Newline-delimited root domains
      --output-root DIR   Output root (default: ~/Recon)
      --rate N            HTTP requests/second, 1-10 (default: 5)
      --ack-scope         Confirm active testing is authorized
      --dry-run           Show and record the sequence without executing it
  -h, --help              Show help
      --version           Show version

FIXED SEQUENCE
  subfinder -> assetfinder -> findomain -> amass -> chaos -> bbot
  -> dnsx -> httpx -> gau -> waybackurls -> katana -> naabu -> nuclei

OUTPUT
  ~/Recon/<domain>/outputs/   Results and final summaries
  ~/Recon/<domain>/logs/      Commands plus per-tool stdout/stderr logs
EOF
}

die() { printf '[!] %s\n' "$*" >&2; exit 1; }
info() { printf '[+] %s\n' "$*"; }
warn() { printf '[~] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
need_value() { [[ $# -ge 2 && -n "${2:-}" ]] || die "Missing value for $1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) need_value "$@"; DOMAIN="$2"; shift 2 ;;
    -l|--list) need_value "$@"; LIST_FILE="$2"; shift 2 ;;
    --output-root) need_value "$@"; OUTPUT_ROOT="$2"; shift 2 ;;
    --rate) need_value "$@"; RATE="$2"; shift 2 ;;
    --ack-scope) ACK_SCOPE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --version) printf '%s\n' "$VERSION"; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

[[ -n "$DOMAIN" || -n "$LIST_FILE" ]] || die "Use --domain or --list"
[[ -z "$DOMAIN" || -z "$LIST_FILE" ]] || die "Use only one of --domain or --list"
[[ "$RATE" =~ ^([1-9]|10)$ ]] || die "--rate must be an integer from 1 through 10"
[[ -z "$LIST_FILE" || -f "$LIST_FILE" ]] || die "Domain list not found: $LIST_FILE"
if [[ "$DRY_RUN" -eq 0 && "$ACK_SCOPE" -ne 1 ]]; then
  die "The fixed pipeline includes active commands; rerun with --ack-scope"
fi

TMP_DOMAINS="$(mktemp)"
TMP_VALID_DOMAINS="$(mktemp)"
trap 'rm -f "$TMP_DOMAINS" "$TMP_VALID_DOMAINS"' EXIT
if [[ -n "$DOMAIN" ]]; then printf '%s\n' "$DOMAIN" >"$TMP_DOMAINS"; else cp "$LIST_FILE" "$TMP_DOMAINS"; fi

if ! python3 - "$TMP_DOMAINS" >"$TMP_VALID_DOMAINS" <<'PY'
import re, sys
seen=set()
pat=re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
for raw in open(sys.argv[1], encoding="utf-8", errors="replace"):
    value=raw.split("#",1)[0].strip().lower().rstrip(".")
    if not value: continue
    if not pat.fullmatch(value):
        print(f"invalid domain: {value}", file=sys.stderr)
        raise SystemExit(2)
    if value not in seen:
        seen.add(value); print(value)
PY
then
  die "Invalid domain input"
fi
mapfile -t DOMAINS <"$TMP_VALID_DOMAINS"
[[ ${#DOMAINS[@]} -gt 0 ]] || die "No valid domains supplied"

shell_join() {
  local out="" q arg
  for arg in "$@"; do printf -v q '%q' "$arg"; out+="${out:+ }$q"; done
  printf '%s' "$out"
}

count_lines() {
  [[ -f "$1" ]] && awk 'NF {n++} END {print n+0}' "$1" || printf '0\n'
}

record_stage() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$STAGE_FILE"
}

redact_stream() {
  python3 -u -c '
import os, pathlib, re, sys
secrets=[]
for name,value in os.environ.items():
    if re.search(r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", name, re.I) and len(value) >= 4:
        secrets.append(value)
chaos=pathlib.Path.home()/".config/chaos/pdcp_api_key"
if chaos.is_file():
    value=chaos.read_text(errors="replace").strip()
    if len(value) >= 4: secrets.append(value)
bbot=pathlib.Path.home()/".config/bbot/secrets.yml"
if bbot.is_file():
    for line in bbot.read_text(errors="replace").splitlines():
        match=re.match(r"\s*(?:api_key|api_token|token|secret)\s*:\s*(.+)", line, re.I)
        if match:
            value=match.group(1).split("#",1)[0].strip().strip(chr(34)).strip(chr(39))
            if len(value) >= 4: secrets.append(value)
secrets=sorted(set(secrets), key=len, reverse=True)
for line in sys.stdin:
    for secret in secrets: line=line.replace(secret,"[REDACTED]")
    sys.stdout.write(line); sys.stdout.flush()
'
}

run_stage() {
  local name="$1" outfile="$2"; shift 2
  local stdout_log="$LOG_DIR/${name}.stdout.log"
  local stderr_log="$LOG_DIR/${name}.stderr.log"
  local started rc elapsed tmp stdout_fifo stderr_fifo stdout_pid stderr_pid
  tmp="${outfile}.tmp.$$"
  stdout_fifo="${tmp}.stdout.fifo"
  stderr_fifo="${tmp}.stderr.fifo"
  mkdir -p "$(dirname "$outfile")"
  printf '%s\n' "$(shell_join "$@")" >>"$LOG_DIR/commands.log"
  printf '\n[%02d/%02d] %s\n' "$STAGE_NUMBER" "$TOTAL_STAGES" "$name"
  printf '[>] %s\n' "$(shell_join "$@")"
  STAGE_NUMBER=$((STAGE_NUMBER + 1))

  if [[ "$DRY_RUN" -eq 1 ]]; then
    : >"$outfile"; : >"$stdout_log"; : >"$stderr_log"
    record_stage "$name" planned 0 0
    return 0
  fi

  started="$(date +%s)"
  rm -f "$tmp" "$stdout_fifo" "$stderr_fifo"
  mkfifo "$stdout_fifo" "$stderr_fifo"
  set +e
  redact_stream <"$stdout_fifo" | tee "$stdout_log" "$tmp" &
  stdout_pid=$!
  redact_stream <"$stderr_fifo" | tee "$stderr_log" >&2 &
  stderr_pid=$!
  "$@" >"$stdout_fifo" 2>"$stderr_fifo"
  rc=$?
  wait "$stdout_pid" "$stderr_pid"
  rm -f "$stdout_fifo" "$stderr_fifo"
  set -e
  elapsed=$(( $(date +%s) - started ))

  if [[ "$rc" -eq 0 ]]; then
    mv "$tmp" "$outfile"
    info "$name finished: $(count_lines "$outfile") lines, ${elapsed}s"
    record_stage "$name" success "$elapsed" "$(count_lines "$outfile")"
  else
    [[ -f "$tmp" ]] && mv "$tmp" "${outfile}.partial" || true
    : >"$outfile"
    warn "$name failed with exit $rc; continuing"
    record_stage "$name" failed "$elapsed" 0
  fi
}

skip_stage() {
  local name="$1" outfile="$2" reason="$3"; shift 3
  local command
  command="$(shell_join "$@")"
  mkdir -p "$(dirname "$outfile")"
  printf '%s\n' "$command" >>"$LOG_DIR/commands.log"
  printf '\n[%02d/%02d] %s\n' "$STAGE_NUMBER" "$TOTAL_STAGES" "$name"
  printf '[>] %s\n' "$command"
  warn "$name skipped: $reason"
  STAGE_NUMBER=$((STAGE_NUMBER + 1))
  : >"$outfile"
  : >"$LOG_DIR/${name}.stdout.log"
  printf '%s\n' "$reason" >"$LOG_DIR/${name}.stderr.log"
  record_stage "$name" skipped 0 0
}

run_tool() {
  local tool="$1" name="$2" outfile="$3"; shift 3
  if [[ "$DRY_RUN" -eq 1 || $(command -v "$tool" 2>/dev/null || true) ]]; then
    run_stage "$name" "$outfile" "$@"
  else
    skip_stage "$name" "$outfile" "$tool is not installed" "$@"
  fi
}

normalize_hosts() {
  local root="$1" output="$2"; shift 2
  python3 - "$root" "$output" "$@" <<'PY'
import pathlib,re,sys
root,output,*names=sys.argv[1:]
out=set()
for name in names:
    p=pathlib.Path(name)
    if not p.is_file(): continue
    for raw in p.read_text(errors="replace").splitlines():
        value=raw.strip().split()[0].lower().lstrip("*.").rstrip(".") if raw.strip() else ""
        if value==root or value.endswith("."+root):
            if re.fullmatch(r"[a-z0-9._-]+",value): out.add(value)
pathlib.Path(output).write_text("".join(x+"\n" for x in sorted(out)))
PY
}

normalize_urls() {
  local root="$1" output="$2"; shift 2
  python3 - "$root" "$output" "$@" <<'PY'
import pathlib,sys
from urllib.parse import urlsplit,urlunsplit
root,output,*names=sys.argv[1:]
out=set()
for name in names:
    p=pathlib.Path(name)
    if not p.is_file(): continue
    for raw in p.read_text(errors="replace").splitlines():
        value=raw.strip().split()[0] if raw.strip() else ""
        if not value.startswith(("http://","https://")): continue
        try: u=urlsplit(value)
        except ValueError: continue
        host=(u.hostname or "").lower().rstrip(".")
        if host==root or host.endswith("."+root):
            out.add(urlunsplit((u.scheme,u.netloc,u.path or "/",u.query,"")))
pathlib.Path(output).write_text("".join(x+"\n" for x in sorted(out)))
PY
}

extract_http_urls() {
  python3 - "$1" "$2" <<'PY'
import json,pathlib,sys
src,dst=map(pathlib.Path,sys.argv[1:]); out=set()
if src.is_file():
    for line in src.read_text(errors="replace").splitlines():
        try: obj=json.loads(line)
        except Exception: continue
        value=obj.get("url") or obj.get("final_url")
        if isinstance(value,str): out.add(value)
dst.write_text("".join(x+"\n" for x in sorted(out)))
PY
}

write_summary() {
  local domain="$1" out="$2"
  python3 - "$domain" "$out" "$STAGE_FILE" "$DRY_RUN" <<'PY'
import json,pathlib,sys
domain=sys.argv[1]; out=pathlib.Path(sys.argv[2]); stage_file=pathlib.Path(sys.argv[3]); dry=bool(int(sys.argv[4]))
def count(path):
    try: return sum(1 for x in path.read_text(errors="replace").splitlines() if x.strip())
    except FileNotFoundError: return 0
stages=[]
for line in stage_file.read_text(errors="replace").splitlines():
    name,status,duration,items=line.split("\t")
    stages.append({"name":name,"status":status,"duration_seconds":int(duration),"output_lines":int(items)})
raw=out/"subdomains"/"raw"
sources={p.stem:count(p) for p in sorted(raw.glob("*.txt"))}
stats={
    "subdomains":count(out/"subdomains"/"all.txt"),
    "resolved_hosts":count(out/"dns"/"resolved.txt"),
    "responsive_web":count(out/"http"/"web-urls.txt"),
    "archived_urls":count(out/"urls"/"all.txt"),
    "crawled_urls":count(out/"crawl"/"katana.txt"),
    "open_ports":count(out/"ports"/"naabu.txt"),
    "nuclei_leads":count(out/"nuclei"/"findings.jsonl"),
}
data={"target":domain,"dry_run":dry,"stages":stages,"statistics":stats,"subdomain_sources":sources}
(out/"summary.json").write_text(json.dumps(data,indent=2)+"\n")
lines=[f"Full summary for {domain}","="*(17+len(domain))]
for key,value in stats.items(): lines.append(f"{key.replace('_',' ').title()}: {value}")
lines.append("\nSubdomain sources:")
for key,value in sources.items(): lines.append(f"  {key}: {value}")
lines.append("\nStages:")
for s in stages: lines.append(f"  {s['name']}: {s['status']} ({s['duration_seconds']}s, {s['output_lines']} lines)")
text="\n".join(lines)+"\n"
(out/"summary.txt").write_text(text)
print("\n"+text,end="")
print(f"Results: {out}")
print(f"Machine summary: {out/'summary.json'}")
PY
}

run_domain() {
  local domain="$1"
  local base="$OUTPUT_ROOT/$domain"
  local out="$base/outputs"
  local raw="$out/subdomains/raw"
  LOG_DIR="$base/logs"
  STAGE_FILE="$LOG_DIR/stages.tsv"
  TOTAL_STAGES=13
  STAGE_NUMBER=1
  mkdir -p "$LOG_DIR" "$raw" "$out/dns" "$out/http" "$out/urls/raw" "$out/crawl" "$out/ports" "$out/nuclei"
  : >"$LOG_DIR/commands.log"; : >"$STAGE_FILE"

  printf '\n=== Quality Recon %s ===\nTarget: %s\nRate: %s requests/second\nResults: %s\n' "$VERSION" "$domain" "$RATE" "$out"

  run_tool subfinder subfinder "$raw/subfinder.txt" subfinder -d "$domain" -all -recursive -silent -rl "$RATE"
  run_tool assetfinder assetfinder "$raw/assetfinder.txt" assetfinder --subs-only "$domain"
  run_tool findomain findomain "$raw/findomain.txt" findomain -t "$domain" -q
  run_tool amass amass "$raw/amass.txt" amass enum -passive -d "$domain"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    run_tool chaos chaos "$raw/chaos.txt" chaos -d "$domain" -silent
  elif [[ -n "${PDCP_API_KEY:-}" || -s "$HOME/.config/chaos/pdcp_api_key" ]]; then
    if [[ -z "${PDCP_API_KEY:-}" ]]; then export PDCP_API_KEY="$(<"$HOME/.config/chaos/pdcp_api_key")"; fi
    run_tool chaos chaos "$raw/chaos.txt" chaos -d "$domain" -silent
  else
    skip_stage chaos "$raw/chaos.txt" "PDCP API key is not configured" chaos -d "$domain" -silent
  fi

  run_tool bbot bbot "$raw/bbot.txt" bbot -t "$domain" -p subdomain-enum -rf passive -s --brief --event-types DNS_NAME -y

  normalize_hosts "$domain" "$out/subdomains/all.txt" "$raw"/*.txt
  info "merged subdomains: $(count_lines "$out/subdomains/all.txt")"

  run_tool dnsx dnsx "$out/dns/resolved.txt" dnsx -l "$out/subdomains/all.txt" -silent -retry 1
  run_tool httpx httpx "$out/http/http.jsonl" httpx -l "$out/dns/resolved.txt" -json -silent -sc -title -server -td -ip -cname -rt -rl "$RATE" -threads 10 -timeout 8 -retries 1
  extract_http_urls "$out/http/http.jsonl" "$out/http/web-urls.txt"

  run_tool gau gau "$out/urls/raw/gau.txt" bash -c 'printf "%s\n" "$1" | gau --subs --threads 2 --timeout 20 --retries 1' _ "$domain"
  run_tool waybackurls waybackurls "$out/urls/raw/waybackurls.txt" bash -c 'printf "%s\n" "$1" | waybackurls' _ "$domain"
  normalize_urls "$domain" "$out/urls/all.txt" "$out/urls/raw/gau.txt" "$out/urls/raw/waybackurls.txt"

  run_tool katana katana "$out/crawl/katana.txt" katana -list "$out/http/web-urls.txt" -silent -d 2 -jc -iqp -fsu -ct 10m -timeout 8 -retry 1 -rl "$RATE" -c 5 -p 5
  run_tool naabu naabu "$out/ports/naabu.txt" naabu -l "$out/dns/resolved.txt" -p 80,443,8080,8443,3000,5000,8000,8888,9000,9090 -rate 100 -c 10 -retries 1 -timeout 800 -ec -silent
  run_tool nuclei nuclei "$out/nuclei/findings.jsonl" nuclei -l "$out/http/web-urls.txt" -jsonl -silent -severity medium,high,critical -exclude-tags fuzz,dos,headless,intrusive -type http,ssl -rl "$RATE" -c 5 -bulk-size 5 -timeout 8 -retries 1

  write_summary "$domain" "$out"
}

mkdir -p "$OUTPUT_ROOT"
for domain in "${DOMAINS[@]}"; do run_domain "$domain"; done

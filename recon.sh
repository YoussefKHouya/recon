#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION="1.2.2"
PROFILE="passive"
OUTPUT_ROOT="${HOME}/Recon"
DOMAIN=""
LIST_FILE=""
ACK_SCOPE=0
DRY_RUN=0
RESUME=0
ENABLE_COMPARE=0
ENABLE_OSMEDEUS=0
ENABLE_ONEFORALL=0
ENABLE_KARMA=0
KARMA_MODE="count"
KARMA_LIMIT=25
KARMA_CVE_ID=""
RATE=10
KARMA_ACTIVE_RATE=""
KARMA_MAX_TARGETS=50
KARMA_TOKEN_FILE="${KARMA_SHODAN_TOKEN_FILE:-${HOME}/.config/quality-recon/shodan.key}"
DNS_WORDLIST=""
RESOLVERS_FILE=""
HTTP_RATE=""
HTTP_THREADS=20
CRAWL_RATE=""
PORT_RATE=100
NUCLEI_RATE=""
CLOUD_RATE=""
KAEFERJAEGER_DIR="${KAEFERJAEGER_DIR:-${HOME}/kaeferjaeger.gay}"
MAX_TIME_MIN=10

usage() {
  cat <<'EOF'
quality-recon: bounded, provenance-preserving bug-bounty recon

USAGE
  recon.sh --domain example.com [options]
  recon.sh --list domains.txt [options]

INPUT
  -d, --domain DOMAIN       One root domain (hostname only; no URL/wildcard)
  -l, --list FILE           Newline-delimited root domains; # comments allowed

EXECUTION
  -p, --profile PROFILE     passive (default), standard, or deep
      --ack-scope           Confirm active probing is permitted for every input
      --resume              Preserve completed/raw artifacts and rerun missing stages
      --dry-run             Create layout and command log without network execution
      --output-root DIR     Root directory (default: ~/Recon)

OPTIONAL MODULES
      --compare             Feed per-tool hostname outputs to ReconCompare
      --osmedeus            Run Osmedeus as a separately measured orchestrator
      --oneforall           Run OneForAll in enforced passive-only mode
      --karma               Run bounded Karma v2-style Shodan recon
      --karma-mode MODE     count, download, ip, asn, cve, cveid, favicon,
                            cdn, leaks, or deep (default: count)
      --karma-limit N       Shodan records per query, max 100 (default: 25)
      --karma-cve-id ID     CVE-YYYY-NNNN for Karma cveid mode
      --karma-active-rate N Override --rate for active Karma
      --karma-max-targets N Active Karma host cap, max 500 (default: 50)
      --karma-token-file F  Shodan key file; key is never written to logs
      --dns-wordlist FILE   Enable bounded PureDNS brute force in deep profile
      --resolvers FILE      Resolver list for PureDNS

BOUNDS
      --rate N              All HTTP stages, max 10 (default: 10)
      --http-rate N         Override --rate for HTTPX
      --crawl-rate N        Override --rate for Katana
      --port-rate N         Naabu packets/sec, max 1000 (default: 100)
      --nuclei-rate N       Override --rate for Nuclei
      --max-time N          Tool maximum minutes, max 60 (default: 10)

OUTPUT
  Recon/<domain>/outputs/ under the selected output root.
  Raw source outputs remain separate; merged files never destroy provenance.

PROFILES
  passive   Passive subdomain and archive collection only.
  standard  Passive + DNS/HTTP/crawl + BBOT and Kaeferjaeger cloud discovery.
  deep      Standard + optional DNS brute force, narrow ports, targeted Nuclei.

NOTES
  Active profiles require --ack-scope. The script does not install tools,
  guess scope, run SQLMap, brute-force logins, spray 403 bypasses, or scan all ports.
EOF
}

die() { printf '[!] %s\n' "$*" >&2; exit 1; }
warn() { printf '[~] %s\n' "$*" >&2; }
info() { printf '[+] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

need_value() {
  [[ $# -ge 2 && -n "${2:-}" ]] || die "Missing value for $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) need_value "$@"; DOMAIN="$2"; shift 2 ;;
    -l|--list) need_value "$@"; LIST_FILE="$2"; shift 2 ;;
    -p|--profile) need_value "$@"; PROFILE="$2"; shift 2 ;;
    --output-root) need_value "$@"; OUTPUT_ROOT="$2"; shift 2 ;;
    --dns-wordlist) need_value "$@"; DNS_WORDLIST="$2"; shift 2 ;;
    --resolvers) need_value "$@"; RESOLVERS_FILE="$2"; shift 2 ;;
    --rate) need_value "$@"; RATE="$2"; shift 2 ;;
    --http-rate) need_value "$@"; HTTP_RATE="$2"; shift 2 ;;
    --crawl-rate) need_value "$@"; CRAWL_RATE="$2"; shift 2 ;;
    --port-rate) need_value "$@"; PORT_RATE="$2"; shift 2 ;;
    --nuclei-rate) need_value "$@"; NUCLEI_RATE="$2"; shift 2 ;;
    --max-time) need_value "$@"; MAX_TIME_MIN="$2"; shift 2 ;;
    --ack-scope) ACK_SCOPE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --resume) RESUME=1; shift ;;
    --compare) ENABLE_COMPARE=1; shift ;;
    --osmedeus) ENABLE_OSMEDEUS=1; shift ;;
    --oneforall) ENABLE_ONEFORALL=1; shift ;;
    --karma) ENABLE_KARMA=1; shift ;;
    --karma-mode) need_value "$@"; KARMA_MODE="$2"; shift 2 ;;
    --karma-limit) need_value "$@"; KARMA_LIMIT="$2"; shift 2 ;;
    --karma-cve-id) need_value "$@"; KARMA_CVE_ID="$2"; shift 2 ;;
    --karma-active-rate) need_value "$@"; KARMA_ACTIVE_RATE="$2"; shift 2 ;;
    --karma-max-targets) need_value "$@"; KARMA_MAX_TARGETS="$2"; shift 2 ;;
    --karma-token-file) need_value "$@"; KARMA_TOKEN_FILE="$2"; shift 2 ;;

    -h|--help) usage; exit 0 ;;
    --version) printf '%s\n' "$VERSION"; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

HTTP_RATE="${HTTP_RATE:-$RATE}"
CRAWL_RATE="${CRAWL_RATE:-$RATE}"
NUCLEI_RATE="${NUCLEI_RATE:-$RATE}"
CLOUD_RATE="${CLOUD_RATE:-$RATE}"
KARMA_ACTIVE_RATE="${KARMA_ACTIVE_RATE:-$RATE}"

[[ -n "$DOMAIN" || -n "$LIST_FILE" ]] || die "Use --domain or --list"
[[ -z "$DOMAIN" || -z "$LIST_FILE" ]] || die "Use only one of --domain or --list"
[[ "$PROFILE" =~ ^(passive|standard|deep)$ ]] || die "Profile must be passive, standard, or deep"
[[ "$KARMA_MODE" =~ ^(count|download|ip|asn|cve|cveid|favicon|cdn|leaks|deep)$ ]] || die "Invalid Karma mode: $KARMA_MODE"
if [[ "$PROFILE" != passive && "$ACK_SCOPE" -ne 1 ]]; then
  die "Active profile '$PROFILE' requires --ack-scope"
fi
if [[ "$ENABLE_KARMA" -eq 1 && "$KARMA_MODE" =~ ^(ip|favicon|cdn|deep)$ && "$ACK_SCOPE" -ne 1 ]]; then
  die "Active Karma mode '$KARMA_MODE' requires --ack-scope"
fi
if [[ ( "$ENABLE_ONEFORALL" -eq 1 || "$ENABLE_OSMEDEUS" -eq 1 ) && "$ACK_SCOPE" -ne 1 ]]; then
  die "OneForAll and Osmedeus require --ack-scope"
fi
for n in "$RATE" "$HTTP_RATE" "$CRAWL_RATE" "$PORT_RATE" "$NUCLEI_RATE" "$CLOUD_RATE" "$MAX_TIME_MIN" "$KARMA_LIMIT" "$KARMA_ACTIVE_RATE" "$KARMA_MAX_TARGETS"; do
  [[ "$n" =~ ^[1-9][0-9]*$ ]] || die "Rate/time values must be positive integers"
done
for n in "$RATE" "$HTTP_RATE" "$CRAWL_RATE" "$NUCLEI_RATE" "$CLOUD_RATE" "$KARMA_ACTIVE_RATE"; do
  [[ "$n" =~ ^([1-9]|10)$ ]] || die "HTTP request rates must be integers from 1 through 10"
done
[[ "$MAX_TIME_MIN" =~ ^([1-9]|[1-5][0-9]|60)$ ]] || die "--max-time must be an integer from 1 through 60"
[[ "$PORT_RATE" =~ ^([1-9]|[1-9][0-9]|[1-9][0-9]{2}|1000)$ ]] || die "--port-rate must be an integer from 1 through 1000"
[[ "$KARMA_LIMIT" =~ ^([1-9]|[1-9][0-9]|100)$ ]] || die "--karma-limit must be an integer from 1 through 100"
[[ "$KARMA_MAX_TARGETS" =~ ^([1-9]|[1-9][0-9]|[1-4][0-9]{2}|500)$ ]] || die "--karma-max-targets must be an integer from 1 through 500"

if [[ "$ENABLE_KARMA" -eq 1 && "$KARMA_MODE" == cveid ]]; then
  [[ "$KARMA_CVE_ID" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]] || die "Karma cveid mode requires --karma-cve-id CVE-YYYY-NNNN"
fi
[[ -z "$LIST_FILE" || -f "$LIST_FILE" ]] || die "Domain list not found: $LIST_FILE"
[[ -z "$DNS_WORDLIST" || -f "$DNS_WORDLIST" ]] || die "DNS wordlist not found: $DNS_WORDLIST"
[[ -z "$RESOLVERS_FILE" || -f "$RESOLVERS_FILE" ]] || die "Resolver list not found: $RESOLVERS_FILE"

TMP_DOMAINS="$(mktemp)"
trap 'rm -f "$TMP_DOMAINS"' EXIT
if [[ -n "$DOMAIN" ]]; then printf '%s\n' "$DOMAIN" > "$TMP_DOMAINS"; else cp "$LIST_FILE" "$TMP_DOMAINS"; fi

mapfile -t DOMAINS < <(python3 - "$TMP_DOMAINS" <<'PY'
import re, sys
seen = set()
pat = re.compile(r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.I)
for raw in open(sys.argv[1], encoding="utf-8", errors="replace"):
    value = raw.split("#", 1)[0].strip().lower().rstrip(".")
    if not value:
        continue
    if "://" in value or value.startswith("*.") or "/" in value or not pat.fullmatch(value):
        print(f"invalid domain: {value}", file=sys.stderr)
        sys.exit(2)
    if value not in seen:
        seen.add(value)
        print(value)
PY
) || die "Invalid domain input"
[[ ${#DOMAINS[@]} -gt 0 ]] || die "No valid domains supplied"

shell_join() {
  local out="" q arg
  for arg in "$@"; do printf -v q '%q' "$arg"; out+="${out:+ }$q"; done
  printf '%s' "$out"
}

record_cmd() {
  local log="$1" arg; shift
  local -a logged=()
  for arg in "$@"; do
    if [[ ( -n "${PDCP_API_KEY:-}" && "$arg" == "$PDCP_API_KEY" ) ||
          ( -n "${SHODAN_API_KEY:-}" && "$arg" == "$SHODAN_API_KEY" ) ]]; then
      logged+=("[REDACTED]")
    else
      logged+=("$arg")
    fi
  done
  printf '%s\n' "$(shell_join "${logged[@]}")" >> "$log"
}

redact_log_file() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  python3 - "$path" "$KARMA_TOKEN_FILE" <<'PY'
import os, pathlib, re, sys
p = pathlib.Path(sys.argv[1])
text = p.read_text(errors="replace")
secrets = []
for name, value in os.environ.items():
    if re.search(r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", name, re.I) and len(value) >= 4:
        secrets.append(value)
for name in sys.argv[2:]:
    q = pathlib.Path(name).expanduser()
    if q.is_file():
        value = q.read_text(errors="replace").strip()
        if len(value) >= 4:
            secrets.append(value)
for secret in sorted(set(secrets), key=len, reverse=True):
    text = text.replace(secret, "[REDACTED]")
p.write_text(text)
PY
}

atomic_publish_dir() {
  local new_dir="$1" current_dir="$2"
  python3 - "$new_dir" "$current_dir" <<'PY'
import ctypes, os, pathlib, sys
new = pathlib.Path(sys.argv[1])
current = pathlib.Path(sys.argv[2])
if not new.is_dir():
    raise SystemExit("replacement directory missing")
if not current.exists():
    os.replace(new, current)
    raise SystemExit(0)
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = libc.renameat2
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int
AT_FDCWD = -100
RENAME_EXCHANGE = 2
if renameat2(AT_FDCWD, os.fsencode(new), AT_FDCWD, os.fsencode(current), RENAME_EXCHANGE) != 0:
    errno = ctypes.get_errno()
    raise OSError(errno, os.strerror(errno))
PY
}

run_capture() {
  local domain_dir="$1" label="$2" outfile="$3"; shift 3
  local cmdlog="$domain_dir/logs/commands.log" errlog="$domain_dir/logs/${label}.stderr.log"
  record_cmd "$cmdlog" "$@"
  if [[ "$RESUME" -eq 1 && -s "$outfile" ]]; then info "$label: resume skip"; return 0; fi
  if [[ "$DRY_RUN" -eq 1 ]]; then : > "$outfile"; return 0; fi
  info "$label"
  if timeout --signal=TERM --kill-after=15s "$((MAX_TIME_MIN * 60))" "$@" >"$outfile.tmp" 2>"$errlog"; then
    redact_log_file "$outfile.tmp"
    redact_log_file "$errlog"
    mv "$outfile.tmp" "$outfile"
  else
    local rc=$?
    redact_log_file "$errlog"
    rm -f "$outfile.tmp"
    warn "$label failed (exit $rc); see $errlog"
    [[ -e "$outfile" ]] || : > "$outfile"
    return 0
  fi
}

normalize_hosts() {
  local root="$1" output="$2"; shift 2
  python3 - "$root" "$output" "$@" <<'PY'
import ipaddress, pathlib, re, sys
from urllib.parse import urlsplit
root, output, *files = sys.argv[1:]
out = set()
for name in files:
    path = pathlib.Path(name)
    if not path.is_file():
        continue
    for raw in path.read_text(errors="replace").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        value = value.split()[0].strip().lower().lstrip("*.").rstrip(".")
        if "://" in value:
            try:
                value = (urlsplit(value).hostname or "").lower().rstrip(".")
            except ValueError:
                continue
        else:
            value = value.split("/", 1)[0]
            if value.count(":") == 1:
                value = value.rsplit(":", 1)[0]
        try:
            ipaddress.ip_address(value)
            continue
        except ValueError:
            pass
        if value == root or value.endswith("." + root):
            if re.fullmatch(r"[a-z0-9._-]+", value):
                out.add(value)
pathlib.Path(output).write_text("".join(x + "\n" for x in sorted(out)))
PY
}

normalize_urls() {
  local root="$1" output="$2"; shift 2
  python3 - "$root" "$output" "$@" <<'PY'
import pathlib, sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
root, output, *files = sys.argv[1:]
out = set()
tracking = {"fbclid","gclid","dclid","msclkid","_ga","mc_cid","mc_eid"}
for name in files:
    path = pathlib.Path(name)
    if not path.is_file(): continue
    for raw in path.read_text(errors="replace").splitlines():
        value = raw.strip().split()[0] if raw.strip() else ""
        if not value.startswith(("http://", "https://")): continue
        try: p = urlsplit(value)
        except ValueError: continue
        host = (p.hostname or "").lower().rstrip(".")
        if not (host == root or host.endswith("." + root)): continue
        if p.scheme not in {"http", "https"}: continue
        query = urlencode(sorted((k, "") for k, _ in parse_qsl(p.query, keep_blank_values=True) if k.lower() not in tracking))
        try: parsed_port = p.port
        except ValueError: continue
        port = f":{parsed_port}" if parsed_port and not ((p.scheme == "http" and parsed_port == 80) or (p.scheme == "https" and parsed_port == 443)) else ""
        out.add(urlunsplit((p.scheme, host + port, p.path or "/", query, "")))
pathlib.Path(output).write_text("".join(x + "\n" for x in sorted(out)))
PY
}

extract_http_urls() {
  local jsonl="$1" output="$2"
  python3 - "$jsonl" "$output" <<'PY'
import json, pathlib, sys
src, dst = map(pathlib.Path, sys.argv[1:])
out = set()
if src.is_file():
    for line in src.read_text(errors="replace").splitlines():
        try: obj = json.loads(line)
        except Exception: continue
        url = obj.get("url") or obj.get("final_url")
        if isinstance(url, str) and url.startswith(("http://", "https://")): out.add(url)
dst.write_text("".join(x + "\n" for x in sorted(out)))
PY
}

run_oneforall() {
  local domain="$1"
  local domain_dir="$2"
  local outfile="$3"
  local cmdlog="$domain_dir/logs/commands.log"
  local home_dir="${ONEFORALL_HOME:-$HOME/tools/OneForAll}"
  local python="$home_dir/.venv/bin/python"
  local stdout_log="$domain_dir/logs/oneforall.stdout.log" stderr_log="$domain_dir/logs/oneforall.stderr.log"
  [[ -x "$python" ]] || python="${PYTHON_BIN:-python3}"
  local cmd=("$python" oneforall.py --target "$domain" --brute False --dns False --req False --takeover False --fmt csv run)
  record_cmd "$cmdlog" bash -c "cd <ONEFORALL_HOME> && ${cmd[*]}"
  if [[ "$RESUME" -eq 1 && -s "$outfile" ]]; then info "oneforall: resume skip"; return; fi
  if [[ "$DRY_RUN" -eq 1 ]]; then : > "$outfile"; return; fi
  if [[ ! -f "$home_dir/oneforall.py" ]]; then warn "OneForAll missing: $home_dir"; [[ -e "$outfile" ]] || : > "$outfile"; return; fi
  local tmp="${outfile}.tmp.$$" started
  started="$(date +%s)"
  rm -f "$tmp"
  set +e
  (cd "$home_dir" && timeout --signal=TERM --kill-after=15s "$((MAX_TIME_MIN * 60))" "${cmd[@]}") >"$stdout_log" 2>"$stderr_log"
  local rc=$?
  set -e
  redact_log_file "$stdout_log"
  redact_log_file "$stderr_log"
  if [[ "$rc" -eq 0 ]]; then
    "$python" - "$home_dir" "$domain" "$tmp" "$started" <<'PY'
import csv
import pathlib
import sys

base = pathlib.Path(sys.argv[1])
domain = sys.argv[2]
out = pathlib.Path(sys.argv[3])
started = int(sys.argv[4])
values = set()
for path in base.rglob("*.csv"):
    try:
        if path.stat().st_mtime < started - 5:
            continue
        with path.open(encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle):
                value = (row.get("subdomain") or row.get("domain") or "").strip().lower().rstrip(".")
                if value == domain or value.endswith("." + domain):
                    values.add(value)
    except (OSError, csv.Error):
        continue
out.write_text("".join(value + "\n" for value in sorted(values)), encoding="utf-8")
PY
    mv "$tmp" "$outfile"
  else
    rm -f "$tmp"
    warn "OneForAll failed; see $stderr_log"
    [[ -e "$outfile" ]] || : > "$outfile"
  fi
}

run_karma() {
  local domain="$1"
  local domain_dir="$2"
  local karma_out="$3"
  local raw_out="$4"
  local cmdlog="$domain_dir/logs/commands.log"
  local wrapper="${KARMA_WRAPPER:-karma-v2-safe}"
  local stdout_log="$domain_dir/logs/karma.stdout.log" stderr_log="$domain_dir/logs/karma.stderr.log"
  local cmd=("$wrapper" --domain "$domain" --output "$karma_out" --mode "$KARMA_MODE" --limit "$KARMA_LIMIT" --token-file "$KARMA_TOKEN_FILE" --active-rate "$KARMA_ACTIVE_RATE" --max-targets "$KARMA_MAX_TARGETS" --max-minutes "$MAX_TIME_MIN")
  [[ -n "$KARMA_CVE_ID" ]] && cmd+=(--cve-id "$KARMA_CVE_ID")
  [[ "$ACK_SCOPE" -eq 1 ]] && cmd+=(--ack-scope)
  record_cmd "$cmdlog" "${cmd[@]}"
  if [[ "$RESUME" -eq 1 && -s "$raw_out" && -s "$karma_out/hosts.txt" ]]; then info "karma: resume skip"; return; fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    mkdir -p "$karma_out"
    : > "$karma_out/hosts.txt"
    : > "$raw_out"
    return
  fi
  if ! have "$wrapper"; then
    warn "Karma wrapper missing: $wrapper"
    mkdir -p "$karma_out"
    [[ -e "$raw_out" ]] || : > "$raw_out"
    return
  fi
  local tmp_out="${karma_out}.tmp.$$"
  local -a exec_cmd=("$wrapper" --domain "$domain" --output "$tmp_out" --mode "$KARMA_MODE" --limit "$KARMA_LIMIT" --token-file "$KARMA_TOKEN_FILE" --active-rate "$KARMA_ACTIVE_RATE" --max-targets "$KARMA_MAX_TARGETS" --max-minutes "$MAX_TIME_MIN")
  [[ -n "$KARMA_CVE_ID" ]] && exec_cmd+=(--cve-id "$KARMA_CVE_ID")
  [[ "$ACK_SCOPE" -eq 1 ]] && exec_cmd+=(--ack-scope)
  rm -rf "$tmp_out"
  if timeout --signal=TERM --kill-after=15s "$((MAX_TIME_MIN * 60 + 60))" "${exec_cmd[@]}" >"$stdout_log" 2>"$stderr_log"; then
    redact_log_file "$stdout_log"
    redact_log_file "$stderr_log"
    if [[ -f "$tmp_out/hosts.txt" ]]; then
      if atomic_publish_dir "$tmp_out" "$karma_out"; then
        rm -rf "$tmp_out"
        cp "$karma_out/hosts.txt" "${raw_out}.tmp.$$"
        mv "${raw_out}.tmp.$$" "$raw_out"
      else
        rm -rf "$tmp_out"
        warn "Karma output publication failed; previous artifact preserved"
        [[ -e "$raw_out" ]] || : > "$raw_out"
      fi
    else
      rm -rf "$tmp_out"
      warn "Karma completed without hosts.txt"
      [[ -e "$raw_out" ]] || : > "$raw_out"
    fi
  else
    redact_log_file "$stdout_log"
    redact_log_file "$stderr_log"
    rm -rf "$tmp_out"
    warn "Karma mode '$KARMA_MODE' did not complete; see $stderr_log"
    [[ -e "$raw_out" ]] || : > "$raw_out"
  fi
}

run_cloud() {
  local domain="$1" base="$2" out="$3"
  local cloud="$out/cloud"
  local bbot_out="$cloud/bbot" kaefer_out="$cloud/kaeferjaeger"
  local cmdlog="$base/logs/commands.log" scan_name="cloud-${domain//./-}"
  local origin_script="$KAEFERJAEGER_DIR/originiphunter.py"
  local origin_ok=0 bbot_ok=0
  local origin_tmp="$kaefer_out/.sni-associations.txt.tmp.$$"
  local bbot_tmp="$cloud/.bbot.tmp.$$"
  mkdir -p "$bbot_out" "$kaefer_out"

  local origin_cmd=(python3 "$origin_script" --url "$domain" --workers 2 --skip-malformed --output "$kaefer_out/sni-associations.txt" --force)
  local origin_exec_cmd=(python3 "$origin_script" --url "$domain" --workers 2 --skip-malformed --output "$origin_tmp" --force)
  record_cmd "$cmdlog" "${origin_cmd[@]}"

  local bbot_cmd=(bbot -t "$domain" -m bucket_amazon bucket_google bucket_microsoft bucket_firebase azure_tenant --strict-scope -om json txt -n "$scan_name" -o "$bbot_out" -y -c "web.http_rate_limit=$CLOUD_RATE" modules.bucket_amazon.permutations=false modules.bucket_google.permutations=false modules.bucket_microsoft.permutations=false modules.bucket_firebase.permutations=false)
  local bbot_exec_cmd=(bbot -t "$domain" -m bucket_amazon bucket_google bucket_microsoft bucket_firebase azure_tenant --strict-scope -om json txt -n "$scan_name" -o "$bbot_tmp" -y -c "web.http_rate_limit=$CLOUD_RATE" modules.bucket_amazon.permutations=false modules.bucket_google.permutations=false modules.bucket_microsoft.permutations=false modules.bucket_firebase.permutations=false)
  record_cmd "$cmdlog" "${bbot_cmd[@]}"

  if [[ "$RESUME" -eq 1 && -f "$cloud/complete.marker" ]]; then
    info "cloud: resume skip"
    return
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    : > "$kaefer_out/sni-associations.txt"
    : > "$cloud/summary.json"
    return
  fi

  rm -f "$cloud/complete.marker" "$origin_tmp"
  rm -rf "$bbot_tmp"

  if [[ -f "$origin_script" ]]; then
    set +e
    timeout --signal=TERM --kill-after=15s "$((MAX_TIME_MIN * 60))" "${origin_exec_cmd[@]}" >"$base/logs/kaeferjaeger.stdout.log" 2>"$base/logs/kaeferjaeger.stderr.log"
    local origin_rc=$?
    set -e
    redact_log_file "$base/logs/kaeferjaeger.stdout.log"
    redact_log_file "$base/logs/kaeferjaeger.stderr.log"
    if [[ ( "$origin_rc" -eq 0 || "$origin_rc" -eq 3 ) && -f "$origin_tmp" ]]; then
      redact_log_file "$origin_tmp"
      mv "$origin_tmp" "$kaefer_out/sni-associations.txt"
      origin_ok=1
    else
      rm -f "$origin_tmp"
      warn "Kaeferjaeger failed (exit $origin_rc); see $base/logs/kaeferjaeger.stderr.log"
      [[ -e "$kaefer_out/sni-associations.txt" ]] || : > "$kaefer_out/sni-associations.txt"
    fi
  else
    warn "Kaeferjaeger script missing: $origin_script"
    [[ -e "$kaefer_out/sni-associations.txt" ]] || : > "$kaefer_out/sni-associations.txt"
  fi

  if have bbot; then
    if timeout --signal=TERM --kill-after=30s "$((MAX_TIME_MIN * 60))" "${bbot_exec_cmd[@]}" >"$base/logs/bbot-cloud.stdout.log" 2>"$base/logs/bbot-cloud.stderr.log" && [[ -d "$bbot_tmp" ]]; then
      if atomic_publish_dir "$bbot_tmp" "$bbot_out"; then
        rm -rf "$bbot_tmp"
        bbot_ok=1
      else
        rm -rf "$bbot_tmp"
        warn "BBOT output publication failed; previous artifact preserved"
      fi
    else
      rm -rf "$bbot_tmp"
      warn "BBOT cloud discovery failed; see $base/logs/bbot-cloud.stderr.log"
    fi
    redact_log_file "$base/logs/bbot-cloud.stdout.log"
    redact_log_file "$base/logs/bbot-cloud.stderr.log"
  else
    warn "bbot missing"
  fi

  python3 - "$cloud" "$domain" <<'PY'
import json, pathlib, sys
cloud, domain = pathlib.Path(sys.argv[1]), sys.argv[2]
assoc = cloud / "kaeferjaeger" / "sni-associations.txt"
kaefer = sum(1 for x in assoc.read_text(errors="replace").splitlines() if x.strip()) if assoc.is_file() else 0
events = []
for p in (cloud / "bbot").glob("**/output.json"):
    for line in p.read_text(errors="replace").splitlines():
        try: obj = json.loads(line)
        except Exception: continue
        if obj.get("type") in {"STORAGE_BUCKET", "AZURE_TENANT"}:
            events.append({"type": obj.get("type"), "module": obj.get("module"), "data": obj.get("data_json"), "scope": obj.get("scope_description")})
summary = {"domain": domain, "kaeferjaeger_associations": kaefer, "bbot_events": events,
           "note": "Candidates require ownership and exposure validation; no cloud Nuclei or search-engine dorking is run."}
(cloud / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
PY
  if [[ "$origin_ok" -eq 1 && "$bbot_ok" -eq 1 ]]; then
    date -u +%FT%TZ > "$cloud/complete.marker"
  else
    warn "cloud discovery incomplete; resume will retry missing components"
  fi
}

run_domain() {
  local domain="$1"
  local base="$OUTPUT_ROOT/$domain"
  local out="$base/outputs"
  local raw="$out/subdomains/raw"
  mkdir -p "$base/inputs" "$base/logs" "$raw" "$out/dns" "$out/http" "$out/urls/raw" "$out/urls/classified" "$out/crawl" "$out/ports" "$out/nuclei" "$out/osmedeus" "$out/karma" "$out/cloud/bbot" "$out/cloud/kaeferjaeger" "$out/compare"
  printf '%s\n' "$domain" > "$base/inputs/roots.txt"
  [[ "$RESUME" -eq 1 ]] || : > "$base/logs/commands.log"
  printf '{"domain":"%s","profile":"%s","dry_run":%s,"ack_scope":%s}\n' "$domain" "$PROFILE" "$DRY_RUN" "$ACK_SCOPE" > "$base/logs/run.json"

  if have subfinder || [[ "$DRY_RUN" -eq 1 ]]; then
    run_capture "$base" subfinder "$raw/subfinder.txt" subfinder -d "$domain" -silent -duc -rl 10 -max-time "$MAX_TIME_MIN"
  else warn "subfinder missing"; fi
  if have assetfinder; then run_capture "$base" assetfinder "$raw/assetfinder.txt" assetfinder --subs-only "$domain"; fi
  if have findomain; then run_capture "$base" findomain "$raw/findomain.txt" findomain -t "$domain" -q; fi
  if have amass && [[ "$PROFILE" == deep ]]; then run_capture "$base" amass "$raw/amass.txt" amass enum -passive -d "$domain" -timeout "$MAX_TIME_MIN"; fi
  if have chaos && [[ -n "${PDCP_API_KEY:-}" ]]; then run_capture "$base" chaos "$raw/chaos.txt" chaos -d "$domain" -silent; fi
  if [[ "$ENABLE_ONEFORALL" -eq 1 ]]; then run_oneforall "$domain" "$base" "$raw/oneforall.txt"; fi
  if [[ "$ENABLE_KARMA" -eq 1 ]]; then run_karma "$domain" "$base" "$out/karma" "$raw/karma.txt"; fi
  if [[ "$PROFILE" != passive ]]; then run_cloud "$domain" "$base" "$out"; fi

  mapfile -t raw_files < <(find "$raw" -maxdepth 1 -type f -name '*.txt' | sort)
  normalize_hosts "$domain" "$out/subdomains/all.txt" "${raw_files[@]}"

  if [[ "$ENABLE_OSMEDEUS" -eq 1 ]]; then
    local osm_target="$out/osmedeus/workspace"
    record_cmd "$base/logs/commands.log" osmedeus run -m subdomain-enum -t "$domain" -S "$domain" -W "$out/osmedeus" -w workspace -B gently --timeout 1h
    if [[ "$RESUME" -eq 1 && -s "$raw/osmedeus.txt" ]]; then
      info "osmedeus: resume skip"
    elif [[ "$DRY_RUN" -eq 1 ]]; then
      : > "$raw/osmedeus.txt"
    elif have osmedeus; then
      rm -rf "$osm_target"
      timeout --signal=TERM --kill-after=30s 3600 osmedeus run -m subdomain-enum -t "$domain" -S "$domain" -W "$out/osmedeus" -w workspace -B gently --timeout 1h >"$base/logs/osmedeus.stdout.log" 2>"$base/logs/osmedeus.stderr.log" || true
      redact_log_file "$base/logs/osmedeus.stdout.log"
      redact_log_file "$base/logs/osmedeus.stderr.log"
      local osm_file="$out/osmedeus/$domain/subdomain/subdomain-$domain.txt"
      if [[ -f "$osm_file" ]]; then
        cp "$osm_file" "$raw/osmedeus.txt.tmp"
        mv "$raw/osmedeus.txt.tmp" "$raw/osmedeus.txt"
      else
        [[ -e "$raw/osmedeus.txt" ]] || : > "$raw/osmedeus.txt"
      fi
    else warn "osmedeus missing"; fi
    : "$osm_target"
    mapfile -t raw_files < <(find "$raw" -maxdepth 1 -type f -name '*.txt' | sort)
    normalize_hosts "$domain" "$out/subdomains/all.txt" "${raw_files[@]}"
  fi

  if [[ "$PROFILE" != passive ]]; then
    if [[ "$PROFILE" == deep && -n "$DNS_WORDLIST" && $(command -v puredns || true) ]]; then
      local brute=(puredns bruteforce "$DNS_WORDLIST" "$domain" --quiet)
      [[ -n "$RESOLVERS_FILE" ]] && brute+=(--resolvers "$RESOLVERS_FILE")
      run_capture "$base" puredns-bruteforce "$raw/puredns-bruteforce.txt" "${brute[@]}"
      normalize_hosts "$domain" "$out/subdomains/all.txt" "$out/subdomains/all.txt" "$raw/puredns-bruteforce.txt"
    fi

    if have puredns; then
      local pd=(puredns resolve "$out/subdomains/all.txt" --quiet)
      [[ -n "$RESOLVERS_FILE" ]] && pd+=(--resolvers "$RESOLVERS_FILE")
      run_capture "$base" puredns-resolve "$out/dns/resolved.txt" "${pd[@]}"
      if [[ "$DRY_RUN" -eq 0 && ! -s "$out/dns/resolved.txt" ]] && have dnsx; then
        warn "PureDNS produced no results; falling back to DNSX"
        run_capture "$base" dnsx-resolve "$out/dns/resolved.txt" dnsx -l "$out/subdomains/all.txt" -silent -retry 1
      fi
    elif have dnsx; then
      run_capture "$base" dnsx-resolve "$out/dns/resolved.txt" dnsx -l "$out/subdomains/all.txt" -silent -retry 1
    else
      warn "puredns/dnsx missing; using discovered hosts as HTTP input"
      cp "$out/subdomains/all.txt" "$out/dns/resolved.txt"
    fi

    if have httpx || [[ "$DRY_RUN" -eq 1 ]]; then
      run_capture "$base" httpx "$out/http/http.jsonl" httpx -l "$out/dns/resolved.txt" -json -silent -sc -cl -ct -location -title -server -td -ip -cname -hash sha256 -rt -rl "$HTTP_RATE" -threads "$HTTP_THREADS" -timeout 8 -retries 1 -ports http:80,8080,8000,8888,3000,5000,https:443,8443
      extract_http_urls "$out/http/http.jsonl" "$out/http/web-urls.txt"
    else warn "httpx missing"; : > "$out/http/web-urls.txt"; fi
  else
    : > "$out/http/web-urls.txt"
  fi

  if have gau || [[ "$DRY_RUN" -eq 1 ]]; then run_capture "$base" gau "$out/urls/raw/gau.txt" bash -c "printf '%s\\n' \"\$1\" | gau --subs --threads 2 --timeout 20 --retries 1" _ "$domain"; fi
  if have waybackurls; then run_capture "$base" waybackurls "$out/urls/raw/waybackurls.txt" bash -c "printf '%s\\n' \"\$1\" | waybackurls" _ "$domain"; fi
  if have waymore && [[ "$PROFILE" == deep ]]; then
    record_cmd "$base/logs/commands.log" waymore -i "$domain" -mode U -oU "$out/urls/raw/waymore.txt" -p 2 -r 1 -t 20
    if [[ "$RESUME" -eq 1 && -s "$out/urls/raw/waymore.txt" ]]; then
      info "waymore: resume skip"
    elif [[ "$DRY_RUN" -eq 1 ]]; then
      : > "$out/urls/raw/waymore.txt"
    else
      local waymore_tmp="$out/urls/raw/waymore.txt.tmp.$$"
      if waymore -i "$domain" -mode U -oU "$waymore_tmp" -p 2 -r 1 -t 20 >"$base/logs/waymore.stdout.log" 2>"$base/logs/waymore.stderr.log"; then
        redact_log_file "$base/logs/waymore.stdout.log"
        redact_log_file "$base/logs/waymore.stderr.log"
        mv "$waymore_tmp" "$out/urls/raw/waymore.txt"
      else
        redact_log_file "$base/logs/waymore.stdout.log"
        redact_log_file "$base/logs/waymore.stderr.log"
        rm -f "$waymore_tmp"
        [[ -e "$out/urls/raw/waymore.txt" ]] || : > "$out/urls/raw/waymore.txt"
      fi
    fi
  fi
  mapfile -t url_files < <(find "$out/urls/raw" -maxdepth 1 -type f -name '*.txt' | sort)
  normalize_urls "$domain" "$out/urls/all.txt" "${url_files[@]}"

  if [[ "$PROFILE" != passive && ( "$DRY_RUN" -eq 1 || -s "$out/http/web-urls.txt" ) ]]; then
    if have katana || [[ "$DRY_RUN" -eq 1 ]]; then
      run_capture "$base" katana "$out/crawl/katana.txt" katana -list "$out/http/web-urls.txt" -silent -d 2 -jc -iqp -fsu -fs rdn -ct 10m -mdp 500 -mrs 2097152 -timeout 8 -retry 1 -rl "$CRAWL_RATE" -c 5 -p 5
      normalize_urls "$domain" "$out/crawl/katana-normalized.txt" "$out/crawl/katana.txt"
      normalize_urls "$domain" "$out/urls/all.txt" "$out/urls/all.txt" "$out/crawl/katana-normalized.txt"
    fi
  fi

  python3 - "$out/urls/all.txt" "$out/urls/classified" <<'PY'
import pathlib, re, sys
src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]); dst.mkdir(parents=True, exist_ok=True)
patterns={
"javascript":r"\.js(?:\?|$)", "api":r"/(?:api|rest|v[0-9]+|graphql|gql)(?:/|\?|$)",
"auth":r"login|signin|signup|oauth|saml|oidc|callback|reset|password|token",
"uploads":r"upload|attachment|document|avatar|media|download",
"admin":r"/(?:admin|internal|debug|manage|console|staging|dev)(?:/|\?|$)",
"openapi":r"swagger|openapi|api-docs|redoc|graphiql|playground",
"parameters":r"\?[^#]*="}
lines=src.read_text(errors="replace").splitlines() if src.is_file() else []
for name, pat in patterns.items():
    vals=sorted({x for x in lines if re.search(pat,x,re.I)})
    (dst/f"{name}.txt").write_text("".join(x+"\n" for x in vals))
PY

  if [[ "$PROFILE" == deep && ( "$DRY_RUN" -eq 1 || -s "$out/dns/resolved.txt" ) ]]; then
    if have naabu || [[ "$DRY_RUN" -eq 1 ]]; then
      run_capture "$base" naabu "$out/ports/naabu.txt" naabu -l "$out/dns/resolved.txt" -p 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200 -rate "$PORT_RATE" -c 10 -retries 1 -timeout 800 -ec -silent
    fi
    if have nuclei || [[ "$DRY_RUN" -eq 1 ]]; then
      run_capture "$base" nuclei "$out/nuclei/findings.jsonl" nuclei -l "$out/http/web-urls.txt" -jsonl -silent -severity medium,high,critical -exclude-tags fuzz,dos,headless,intrusive -type http,ssl -rl "$NUCLEI_RATE" -c 5 -bulk-size 5 -timeout 8 -retries 1
    fi
  fi

  if [[ "$ENABLE_COMPARE" -eq 1 ]]; then
    if [[ "$RESUME" -eq 1 && -s "$out/compare/report.json" && -s "$out/compare/report.txt" ]]; then
      info "reconcompare: resume skip"
    else
      local run_id="${domain}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
      printf '%s\n' "$run_id" > "$out/compare/run-id.txt"
      record_cmd "$base/logs/commands.log" reconcompare report --run "$run_id" --json
      if [[ "$DRY_RUN" -eq 1 ]]; then : > "$out/compare/report.json"; : > "$out/compare/report.txt";
    elif have reconcompare; then
      for file in "$raw"/*.txt; do
        [[ -s "$file" ]] || continue
        reconcompare ingest --run "$run_id" --domain "$domain" --tool "$(basename "$file" .txt)" --file "$file" >> "$base/logs/reconcompare-ingest.log" 2>&1 || true
      done
      reconcompare report --run "$run_id" > "$out/compare/report.txt.tmp" 2>"$base/logs/reconcompare.stderr.log" && mv "$out/compare/report.txt.tmp" "$out/compare/report.txt" || rm -f "$out/compare/report.txt.tmp"
      reconcompare report --run "$run_id" --json > "$out/compare/report.json.tmp" 2>>"$base/logs/reconcompare.stderr.log" && mv "$out/compare/report.json.tmp" "$out/compare/report.json" || rm -f "$out/compare/report.json.tmp"
      redact_log_file "$base/logs/reconcompare-ingest.log"
      redact_log_file "$base/logs/reconcompare.stderr.log"
    else warn "reconcompare missing"; fi
    fi
  fi

  python3 - "$base" <<'PY'
import json, pathlib, sys
b=pathlib.Path(sys.argv[1]); out=b/'outputs'
def count(p):
    try: return sum(1 for x in p.read_text(errors='replace').splitlines() if x.strip())
    except FileNotFoundError: return 0
summary={
'domain': b.name,
'subdomains': count(out/'subdomains/all.txt'),
'resolved': count(out/'dns/resolved.txt'),
'web_urls': count(out/'http/web-urls.txt'),
'urls': count(out/'urls/all.txt'),
'crawl_urls': count(out/'crawl/katana-normalized.txt'),
'ports': count(out/'ports/naabu.txt'),
'nuclei_findings': count(out/'nuclei/findings.jsonl')}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary))
PY
}

mkdir -p "$OUTPUT_ROOT"
for domain in "${DOMAINS[@]}"; do run_domain "$domain"; done

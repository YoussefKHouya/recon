#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

if (( BASH_VERSINFO[0] < 4 )); then
  printf '[!] quality-recon requires Bash 4 or newer\n' >&2
  exit 1
fi

VERSION="4.0.2"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_RESOLVERS_FILE="$SCRIPT_DIR/resolver.txt"
OUTPUT_ROOT="${HOME}/Recon"
DOMAIN=""
LIST_FILE=""
DRY_RUN=0
DEEP=0
RATE=5
DNS_RATE=100
PORT_RATE=100
CRAWL_DEPTH=2
RESOLVERS_FILE=""
KAEFERJAEGER_DIR="${KAEFERJAEGER_DIR:-${HOME}/kaeferjaeger.gay}"

# =============================================================================
# PIPELINE CONTROL — edit these lists to add, remove, or reorder work.
# CLI overrides: --stages, --subdomain-tools, --archive-tools, --cloud-tools.
# =============================================================================
STAGES_CSV="subdomains,compare,dns,alive,stack,archives,crawl,url-analysis,cloud"
SUBDOMAIN_TOOLS_CSV="subfinder,assetfinder,findomain,bbot,osmedeus"
ARCHIVE_TOOLS_CSV="gau,waybackurls,waymore"
CLOUD_TOOLS_CSV="bbot-cloud,kaeferjaeger"

# =============================================================================
# COMMAND BUILDERS — one isolated function per external tool. To add a tool:
# 1. add its name to the relevant CSV above;
# 2. add a builder here;
# 3. add one case entry in the relevant run_* stage.
# No command string is eval'd.
# =============================================================================
CMD=()
build_subfinder_cmd() { CMD=(subfinder -d "$1" -all -recursive -silent -rl "$RATE"); }
build_assetfinder_cmd() { CMD=(assetfinder --subs-only "$1"); }
build_findomain_cmd() { CMD=(findomain -t "$1" -q); }
build_bbot_subdomain_cmd() {
  CMD=(bbot -t "$1" -p subdomain-enum -rf passive --silent --brief --event-types DNS_NAME -y
       -c "web.http_rate_limit=$RATE")
}
build_osmedeus_cmd() {
  CMD=(osmedeus run -m enum-subdomain -t "$1" -S "$1" -W "$2" -B gently --timeout 1h)
}
build_dnsx_cmd() { CMD=(dnsx -l "$1" -silent -retry 1 -rl "$DNS_RATE"); }
build_puredns_cmd() {
  CMD=(puredns resolve "$1" --quiet --rate-limit "$DNS_RATE")
  [[ -z "$RESOLVERS_FILE" ]] || CMD+=(--resolvers "$RESOLVERS_FILE")
}
build_httpx_cmd() {
  CMD=(httpx -l "$1" -json -silent -sc -cl -ct -location -title -server -td -ip -cname
       -hash sha256 -rt -rl "$RATE" -threads 20 -timeout 8 -retries 1
       -ports http:80,8080,8000,8888,3000,5000,https:443,8443)
}
build_gau_cmd() { CMD=(bash -c 'printf "%s\n" "$1" | gau --subs --threads 2 --timeout 20 --retries 1' _ "$1"); }
build_waybackurls_cmd() { CMD=(bash -c 'printf "%s\n" "$1" | waybackurls' _ "$1"); }
build_waymore_cmd() { CMD=(waymore -i "$1" -mode U -oU "$2" -p 2 -r 1 -t 20); }
build_katana_cmd() {
  CMD=(katana -list "$1" -silent -d "$CRAWL_DEPTH" -jc -iqp -fsu -fs rdn
       -ct 10m -mdp 500 -mrs 2097152 -timeout 8 -retry 1 -rl "$RATE" -c 5 -p 5)
}
build_bbot_cloud_cmd() {
  CMD=(bbot -t "$1" -m bucket_amazon bucket_google bucket_microsoft bucket_firebase azure_tenant
       --strict-scope -om json txt -n "cloud-${1//./-}" -o "$2" -y
       -c "web.http_rate_limit=$RATE"
       modules.bucket_amazon.permutations=false modules.bucket_google.permutations=false
       modules.bucket_microsoft.permutations=false modules.bucket_firebase.permutations=false)
}
build_kaeferjaeger_cmd() {
  CMD=(python3 "$KAEFERJAEGER_DIR/originiphunter.py" --url "$1" --workers 2
       --skip-malformed --output "$2" --force)
}
build_naabu_cmd() {
  CMD=(naabu -l "$1" -p 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200
       -rate "$PORT_RATE" -c 10 -retries 1 -timeout 800 -ec -silent)
}
build_nuclei_cmd() {
  CMD=(nuclei -l "$1" -jsonl -silent -severity medium,high,critical
       -exclude-tags fuzz,dos,headless,intrusive -type http,ssl -rl "$RATE"
       -c 5 -bulk-size 5 -timeout 8 -retries 1)
}

usage() {
  cat <<'EOF'
quality-recon: ordered, modular reconnaissance pipeline

DEFAULT ORDER
  1. subdomains    Subfinder, Assetfinder, Findomain, passive BBOT, Osmedeus
  2. compare       ReconCompare plus local coverage/unique/overlap report
  3. dns           PureDNS with DNSX fallback
  4. alive         HTTPX responsive-service inventory
  5. stack         Parse HTTPX technology/framework/service evidence
  6. archives      GAU, Waybackurls, Waymore
  7. crawl         Katana against responsive web URLs
  8. url-analysis  Merge URLs; extract APIs, JS, auth, uploads, admin and docs
  9. cloud         BBOT cloud modules and Kaeferjaeger
  10. ports        Naabu (--deep only)
  11. nuclei       Focused HTTP/SSL leads (--deep only)

DNS and alive checks intentionally run before Katana because crawling dead or
unresolved hosts wastes traffic. ReconCompare runs immediately after subdomain
enumeration so redundant tools are measurable instead of chosen by vibes.

USAGE
  recon.sh --domain example.com [options]
  recon.sh --list domains.txt [options]

AUTHORIZATION
  The default pipeline performs active DNS, HTTP, crawling, and cloud checks.
  Run it only against assets you own or are explicitly authorized to assess.

OPTIONS
  -d, --domain DOMAIN         One root domain
  -l, --list FILE             Domain list; blank lines and # comments allowed
      --output-root DIR       Default: ~/Recon
      --stages CSV            Override ordered stages
      --subdomain-tools CSV   Override subdomain tools
      --archive-tools CSV     Override archive tools
      --cloud-tools CSV       Override cloud tools
      --rate N                Per-tool HTTP ceiling, 1-10 (default: 5)
      --dns-rate N            DNS queries/sec where supported, 1-500 (default: 100)
      --port-rate N           Naabu packets/sec, 1-1000 (default: 100)
      --crawl-depth N         Katana depth, 1-3 (default: 2)
      --resolvers FILE        PureDNS resolver list (default: ./resolver.txt)
      --deep                  Append ports and nuclei stages
      --dry-run               Create a plan without network execution
  -h, --help                  Show help
      --version               Show version

EXAMPLES
  # Full ordered methodology
  ./recon.sh -d example.com

  # Remove overlapping tools after reviewing compare/report.json
  ./recon.sh -d example.com \
    --subdomain-tools subfinder,bbot,osmedeus

  # Only enumerate and compare passive sources
  ./recon.sh -d example.com \
    --stages subdomains,compare \
    --subdomain-tools subfinder,assetfinder,findomain,bbot

OUTPUT
  <root>/<domain>/latest/outputs/
    subdomains/raw/       one file per enumerator
    compare/              ReconCompare and local differential reports
    dns/                  resolved hostnames
    http/                 alive services and HTTPX JSONL
    urls/                 archive+crawl union and classified leads
    cloud/                cloud candidates
    stack/                technologies/frameworks/services

Rate controls are per tool, not a true aggregate ceiling. Assetfinder,
Findomain, archive providers, and Osmedeus do not expose one uniform hard RPS
control; their concurrency is kept low or Osmedeus uses its gently preset.
Scanner and grep output are leads, not verified vulnerabilities.
EOF
}

die() { printf '[!] %s\n' "$*" >&2; exit 1; }
warn() { printf '[~] %s\n' "$*" >&2; }
info() { printf '[+] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
need_value() { [[ $# -ge 2 && -n "${2:-}" ]] || die "Missing value for $1"; }
count_lines() { [[ -f "$1" ]] && awk 'NF {n++} END {print n+0}' "$1" || printf '0\n'; }

CURRENT_CHILD_PID=""
CURRENT_CHILD_GROUP=0
RUN_PUBLISHED=0
run_tracked() {
  local rc
  setsid --wait "$@" & CURRENT_CHILD_GROUP=1
  CURRENT_CHILD_PID=$!
  wait "$CURRENT_CHILD_PID"; rc=$?
  CURRENT_CHILD_PID=""; CURRENT_CHILD_GROUP=0
  return "$rc"
}

cleanup_tmp() {
  [[ -z "${TMP_ROOT:-}" || ! -d "${TMP_ROOT:-}" ]] || rm -rf -- "$TMP_ROOT"
}

handle_signal() {
  local signal="$1" code="$2" attempt
  trap - INT TERM
  if [[ -n "$CURRENT_CHILD_PID" ]]; then
    if [[ "$CURRENT_CHILD_GROUP" -eq 1 ]]; then kill -TERM -- "-$CURRENT_CHILD_PID" 2>/dev/null || true
    else kill -TERM -- "$CURRENT_CHILD_PID" 2>/dev/null || true
    fi
    for attempt in {1..30}; do
      if [[ "$CURRENT_CHILD_GROUP" -eq 1 ]]; then
        kill -0 -- "-$CURRENT_CHILD_PID" 2>/dev/null || break
      else
        kill -0 -- "$CURRENT_CHILD_PID" 2>/dev/null || break
      fi
      sleep 0.1
    done
    if [[ "$CURRENT_CHILD_GROUP" -eq 1 ]]; then kill -KILL -- "-$CURRENT_CHILD_PID" 2>/dev/null || true
    else kill -KILL -- "$CURRENT_CHILD_PID" 2>/dev/null || true
    fi
    wait "$CURRENT_CHILD_PID" 2>/dev/null || true
  fi
  [[ -z "${RUN_TMP_ROOT:-}" || ! -d "${RUN_TMP_ROOT:-}" ]] || rm -rf -- "$RUN_TMP_ROOT"
  if [[ "$RUN_PUBLISHED" -eq 0 && -n "${RUN_DIR:-}" && -d "${RUN_DIR:-}" ]]; then
    printf '{"state":"interrupted","signal":"%s","exit_code":%s}\n' "$signal" "$code" >"$RUN_DIR/interrupted.json"
  fi
  cleanup_tmp
  exit "$code"
}

arm_signal_traps() {
  trap 'handle_signal INT 130' INT
  trap 'handle_signal TERM 143' TERM
}

shell_join() {
  local rendered="" quoted arg
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    rendered+="${rendered:+ }${quoted}"
  done
  printf '%s' "$rendered"
}

parse_lists() {
  IFS=',' read -ra STAGES <<<"$STAGES_CSV"
  IFS=',' read -ra SUBDOMAIN_TOOLS <<<"$SUBDOMAIN_TOOLS_CSV"
  IFS=',' read -ra ARCHIVE_TOOLS <<<"$ARCHIVE_TOOLS_CSV"
  IFS=',' read -ra CLOUD_TOOLS <<<"$CLOUD_TOOLS_CSV"
  [[ ${#STAGES[@]} -gt 0 && ${#SUBDOMAIN_TOOLS[@]} -gt 0 ]] || die "stage/tool lists must not be empty"
}

validate_lists() {
  local item
  declare -A allowed_stages=([subdomains]=1 [compare]=1 [dns]=1 [alive]=1 [archives]=1 [crawl]=1 [url-analysis]=1 [cloud]=1 [stack]=1 [ports]=1 [nuclei]=1)
  declare -A allowed_sub=([subfinder]=1 [assetfinder]=1 [findomain]=1 [bbot]=1 [osmedeus]=1)
  declare -A allowed_archive=([gau]=1 [waybackurls]=1 [waymore]=1)
  declare -A allowed_cloud=([bbot-cloud]=1 [kaeferjaeger]=1)
  declare -A seen=()
  for item in "${STAGES[@]}"; do
    [[ -n "${allowed_stages[$item]:-}" ]] || die "Unknown stage: $item"
    [[ -z "${seen[stage:$item]:-}" ]] || die "Duplicate stage: $item"
    seen[stage:$item]=1
  done
  for item in "${SUBDOMAIN_TOOLS[@]}"; do
    [[ -n "${allowed_sub[$item]:-}" ]] || die "Unknown subdomain tool: $item"
    [[ -z "${seen[sub:$item]:-}" ]] || die "Duplicate subdomain tool: $item"
    seen[sub:$item]=1
  done
  for item in "${ARCHIVE_TOOLS[@]}"; do
    [[ -n "${allowed_archive[$item]:-}" ]] || die "Unknown archive tool: $item"
    [[ -z "${seen[archive:$item]:-}" ]] || die "Duplicate archive tool: $item"
    seen[archive:$item]=1
  done
  for item in "${CLOUD_TOOLS[@]}"; do
    [[ -n "${allowed_cloud[$item]:-}" ]] || die "Unknown cloud tool: $item"
    [[ -z "${seen[cloud:$item]:-}" ]] || die "Duplicate cloud tool: $item"
    seen[cloud:$item]=1
  done
}

validate_stage_dependencies() {
  declare -A index=()
  local i
  for i in "${!STAGES[@]}"; do index["${STAGES[$i]}"]="$i"; done

  require_before() {
    local child="$1" parent="$2"
    [[ -z "${index[$child]+x}" ]] && return 0
    [[ -n "${index[$parent]+x}" ]] || die "Stage '$child' requires earlier stage '$parent'"
    (( index[$parent] < index[$child] )) || die "Stage '$parent' must appear before '$child'"
  }

  require_before compare subdomains
  require_before dns subdomains
  require_before alive dns
  require_before stack alive
  require_before crawl alive
  require_before ports dns
  require_before nuclei alive

  if [[ -n "${index[url-analysis]+x}" ]]; then
    if [[ -n "${index[archives]+x}" && ${index[archives]} -lt ${index[url-analysis]} ]]; then :
    elif [[ -n "${index[crawl]+x}" && ${index[crawl]} -lt ${index[url-analysis]} ]]; then :
    else die "Stage 'url-analysis' requires earlier stage 'archives' and/or 'crawl'"
    fi
  fi
}

validate_domains() {
  local input="$1" output="$2" list_mode="$3"
  python3 - "$input" "$output" "$list_mode" <<'PY'
import pathlib,re,sys
src,dst=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]); list_mode=sys.argv[3]=="1"
pat=re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$",re.I)
seen=[]
for raw in src.read_text(errors="replace").splitlines():
    stripped=raw.strip()
    if list_mode and (not stripped or stripped.startswith("#")): continue
    value=(re.split(r"\s+#",raw,maxsplit=1)[0] if list_mode else stripped).strip().lower()
    if not value: continue
    if not pat.fullmatch(value): print(f"invalid domain: {value}",file=sys.stderr); raise SystemExit(2)
    if value not in seen: seen.append(value)
dst.write_text("".join(x+"\n" for x in seen))
PY
}

redact_file() {
  local source="$1" destination="$2"
  python3 - "$source" "$destination" <<'PY'
import os,pathlib,re,sys
src,dst=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]); values=[]
for name,value in os.environ.items():
    if re.search(r"(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_?KEY|AUTH_?TOKEN)$",name,re.I) and len(value)>=4: values.append(value)
for path in (pathlib.Path.home()/".config/chaos/pdcp_api_key",pathlib.Path.home()/".config/bbot/secrets.yml",pathlib.Path.home()/".config/subfinder/provider-config.yaml"):
    if not path.is_file(): continue
    text=path.read_text(errors="replace")
    if path.name=="pdcp_api_key":
        if len(text.strip())>=4: values.append(text.strip())
    else:
        for line in text.splitlines():
            m=re.match(r"\s*(?:api[_-]?key|api[_-]?token|token|secret|password|access[_-]?key)\s*:\s*(.+)",line,re.I)
            if m:
                value=m.group(1).split("#",1)[0].strip().strip('"').strip("'")
                if len(value)>=4: values.append(value)
text=src.read_text(errors="replace")
for value in sorted(set(values),key=len,reverse=True): text=text.replace(value,"[REDACTED]")
tmp=dst.with_name(dst.name+".tmp"); tmp.write_text(text); tmp.replace(dst)
PY
}

redact_tree() {
  local root="$1"
  python3 - "$root" <<'PY'
import os,pathlib,re,sys
root=pathlib.Path(sys.argv[1]);values=[]
for name,value in os.environ.items():
    if re.search(r"(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_?KEY|AUTH_?TOKEN)$",name,re.I) and len(value)>=4: values.append(value)
for path in (pathlib.Path.home()/".config/chaos/pdcp_api_key",pathlib.Path.home()/".config/bbot/secrets.yml",pathlib.Path.home()/".config/subfinder/provider-config.yaml"):
    if not path.is_file(): continue
    text=path.read_text(errors="replace")
    if path.name=="pdcp_api_key":
        if len(text.strip())>=4: values.append(text.strip())
    else:
        for line in text.splitlines():
            m=re.match(r"\s*(?:api[_-]?key|api[_-]?token|token|secret|password|access[_-]?key)\s*:\s*(.+)",line,re.I)
            if m:
                value=m.group(1).split("#",1)[0].strip().strip('"').strip("'")
                if len(value)>=4: values.append(value)
values=sorted(set(values),key=len,reverse=True)
for path in root.rglob("*"):
    if not path.is_file() or path.is_symlink(): continue
    data=path.read_bytes()
    if b"\x00" in data: continue
    try:text=data.decode("utf-8")
    except UnicodeDecodeError:continue
    for value in values:text=text.replace(value,"[REDACTED]")
    tmp=path.with_name(path.name+".redacting");tmp.write_text(text);tmp.replace(path)
PY
}

record_command() { printf '%s\n' "$(shell_join "$@")" >>"$LOG_DIR/commands.log"; }
record_status() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$STATUS_FILE"; }

run_stdout_tool() {
  local label="$1" binary="$2" outfile="$3"; shift 3
  local stdout_log="$LOG_DIR/${label}.stdout.log" stderr_log="$LOG_DIR/${label}.stderr.log"
  local tmpdir rawout rawerr started rc out_rc err_rc elapsed
  record_command "$@"
  printf '[%02d] %s\n' "$STEP_NUMBER" "$label"; STEP_NUMBER=$((STEP_NUMBER+1))
  if [[ "$DRY_RUN" -eq 1 ]]; then : >"$outfile"; : >"$stdout_log"; : >"$stderr_log"; record_status "$label" planned 0 0; return; fi
  if ! have "$binary"; then
    : >"$outfile"; : >"$stdout_log"; printf '%s missing\n' "$binary" >"$stderr_log"
    case "$label" in
      dns-puredns|dns-dnsx|httpx|katana|naabu|nuclei)
        warn "$label failed: required executable $binary missing"; record_status "$label" failed 0 0; FAILED_COUNT=$((FAILED_COUNT+1));;
      *)
        warn "$label skipped: $binary missing"; record_status "$label" skipped 0 0;;
    esac
    return
  fi
  tmpdir="$(mktemp -d "$RUN_TMP_ROOT/${label}.XXXXXX")"; rawout="$tmpdir/stdout"; rawerr="$tmpdir/stderr"; started="$(date +%s)"
  set +e
  run_tracked "$@" >"$rawout" 2>"$rawerr"; rc=$?
  redact_file "$rawout" "$stdout_log"; out_rc=$?
  redact_file "$rawerr" "$stderr_log"; err_rc=$?
  set -e
  elapsed=$(( $(date +%s)-started ))
  if [[ "$rc" -eq 0 && "$out_rc" -eq 0 && "$err_rc" -eq 0 ]]; then cp -- "$stdout_log" "$outfile"; info "$label completed: $(count_lines "$outfile") items"; record_status "$label" success "$elapsed" "$(count_lines "$outfile")"; SUCCESS_COUNT=$((SUCCESS_COUNT+1)); TOOL_SUCCESS_COUNT=$((TOOL_SUCCESS_COUNT+1)); else : >"$outfile"; warn "$label failed: scanner=$rc capture=$out_rc/$err_rc"; record_status "$label" failed "$elapsed" 0; FAILED_COUNT=$((FAILED_COUNT+1)); fi
  rm -rf -- "$tmpdir"
}

normalize_hosts() {
  local root="$1" output="$2"; shift 2
  python3 - "$root" "$output" "$@" <<'PY'
import pathlib,re,sys
from urllib.parse import urlsplit
root,out,*files=sys.argv[1:]; hosts=set()
pat=re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",re.I)
for filename in files:
 p=pathlib.Path(filename)
 if not p.is_file(): continue
 for raw in p.read_text(errors="replace").splitlines():
  value=raw.strip().split()[0].lower().lstrip("*.").rstrip(".") if raw.strip() else ""
  if "://" in value:
   try:value=(urlsplit(value).hostname or "").lower().rstrip(".")
   except ValueError:continue
  if pat.fullmatch(value) and (value==root or value.endswith("."+root)):hosts.add(value)
tmp=pathlib.Path(out+".tmp");tmp.write_text("".join(x+"\n" for x in sorted(hosts)));tmp.replace(out)
PY
}

normalize_urls() {
  local root="$1" output="$2"; shift 2
  python3 - "$root" "$output" "$@" <<'PY'
import pathlib,sys
from urllib.parse import parse_qsl,urlencode,urlsplit,urlunsplit
root,out,*files=sys.argv[1:]; urls=set(); tracking={"fbclid","gclid","dclid","msclkid","_ga","mc_cid","mc_eid"}
for filename in files:
 p=pathlib.Path(filename)
 if not p.is_file():continue
 for raw in p.read_text(errors="replace").splitlines():
  value=raw.strip().split()[0] if raw.strip() else ""
  if not value.startswith(("http://","https://")):continue
  try:u=urlsplit(value);host=(u.hostname or "").lower().rstrip(".");port=u.port
  except ValueError:continue
  if not(host==root or host.endswith("."+root)):continue
  query=urlencode(sorted((k,"") for k,_ in parse_qsl(u.query,keep_blank_values=True) if k.lower() not in tracking))
  portpart=f":{port}" if port and not((u.scheme=="http" and port==80)or(u.scheme=="https" and port==443)) else ""
  urls.add(urlunsplit((u.scheme,host+portpart,u.path or "/",query,"")))
tmp=pathlib.Path(out+".tmp");tmp.write_text("".join(x+"\n" for x in sorted(urls)));tmp.replace(out)
PY
}

run_osmedeus() {
  local domain="$1" outfile="$2" workspace="$RUN_TMP_ROOT/osmedeus-workspace"
  build_osmedeus_cmd "$domain" "$workspace"; local stdout_log="$LOG_DIR/osmedeus.stdout.log" stderr_log="$LOG_DIR/osmedeus.stderr.log"
  record_command "${CMD[@]}"; printf '[%02d] osmedeus\n' "$STEP_NUMBER"; STEP_NUMBER=$((STEP_NUMBER+1))
  if [[ "$DRY_RUN" -eq 1 ]]; then : >"$outfile"; : >"$stdout_log"; : >"$stderr_log"; record_status osmedeus planned 0 0; return; fi
  if ! have osmedeus; then : >"$outfile"; warn "osmedeus skipped: missing"; record_status osmedeus skipped 0 0; return; fi
  local tmpdir rawout rawerr collected started rc redact_out_rc redact_err_rc collect_rc=1
  tmpdir="$(mktemp -d "$RUN_TMP_ROOT/osmedeus.XXXXXX")"; rawout="$tmpdir/stdout"; rawerr="$tmpdir/stderr"; collected="$tmpdir/collected"; started="$(date +%s)"
  set +e
  run_tracked "${CMD[@]}" >"$rawout" 2>"$rawerr"; rc=$?
  redact_file "$rawout" "$stdout_log"; redact_out_rc=$?
  redact_file "$rawerr" "$stderr_log"; redact_err_rc=$?
  if [[ "$rc" -eq 0 && "$redact_out_rc" -eq 0 && "$redact_err_rc" -eq 0 ]]; then
    python3 - "$domain" "$workspace" "$collected" <<'PY'
import pathlib,sys
domain,root,dst=sys.argv[1],pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3])
files=[root/domain/"subdomain"/f"final-{domain}.txt",root/domain/"subdomain"/f"subdomain-{domain}.txt"]
src=next((p for p in files if p.is_file()),None)
if src is None:raise SystemExit(4)
tmp=dst.with_name(dst.name+".tmp");tmp.write_text(src.read_text(errors="replace"));tmp.replace(dst)
PY
    collect_rc=$?
    if [[ "$collect_rc" -eq 0 ]]; then redact_file "$collected" "$outfile"; collect_rc=$?; fi
  fi
  set -e; rm -rf -- "$tmpdir"
  if [[ "$rc" -eq 0 && "$collect_rc" -eq 0 ]]; then record_status osmedeus success "$(( $(date +%s)-started ))" "$(count_lines "$outfile")"; SUCCESS_COUNT=$((SUCCESS_COUNT+1)); TOOL_SUCCESS_COUNT=$((TOOL_SUCCESS_COUNT+1)); else : >"$outfile"; warn "osmedeus failed: scanner=$rc artifact=$collect_rc"; record_status osmedeus failed "$(( $(date +%s)-started ))" 0; FAILED_COUNT=$((FAILED_COUNT+1)); fi
}

run_subdomains() {
  local domain="$1" raw="$OUT_DIR/subdomains/raw" scoped="$OUT_DIR/subdomains/scoped" tool rawfile
  local before_success="$TOOL_SUCCESS_COUNT"
  mkdir -p -- "$raw" "$scoped"
  for tool in "${SUBDOMAIN_TOOLS[@]}"; do
    case "$tool" in
      subfinder) build_subfinder_cmd "$domain"; run_stdout_tool subfinder subfinder "$raw/subfinder.txt" "${CMD[@]}" ;;
      assetfinder) build_assetfinder_cmd "$domain"; run_stdout_tool assetfinder assetfinder "$raw/assetfinder.txt" "${CMD[@]}" ;;
      findomain) build_findomain_cmd "$domain"; run_stdout_tool findomain findomain "$raw/findomain.txt" "${CMD[@]}" ;;
      bbot) build_bbot_subdomain_cmd "$domain"; run_stdout_tool bbot-subdomain bbot "$raw/bbot.txt" "${CMD[@]}" ;;
      osmedeus) run_osmedeus "$domain" "$raw/osmedeus.txt" ;;
    esac
  done
  for rawfile in "$raw"/*.txt; do
    normalize_hosts "$domain" "$scoped/$(basename -- "$rawfile")" "$rawfile"
  done
  local files=("$scoped"/*.txt) merged_tmp="$OUT_DIR/subdomains/all.txt.tmp"
  normalize_hosts "$domain" "$OUT_DIR/subdomains/all.txt" "${files[@]}"
  { cat -- "$OUT_DIR/subdomains/all.txt"; printf '%s\n' "$domain"; } | LC_ALL=C sort -u >"$merged_tmp"
  mv -f -- "$merged_tmp" "$OUT_DIR/subdomains/all.txt"
  if [[ "$DRY_RUN" -eq 0 && "$TOOL_SUCCESS_COUNT" -eq "$before_success" ]]; then
    warn "subdomains failed: no selected enumerator completed"
    record_status subdomains failed 0 "$(count_lines "$OUT_DIR/subdomains/all.txt")"
    FAILED_COUNT=$((FAILED_COUNT+1))
  fi
}

run_compare() {
  local domain="$1" raw="$OUT_DIR/subdomains/scoped" compare="$OUT_DIR/compare" run_id="${domain}-${RUN_ID}" file
  mkdir -p -- "$compare"
  python3 - "$domain" "$raw" "$compare/report.json" "$compare/report.txt" <<'PY'
import json,pathlib,sys
domain,raw,jout,tout=sys.argv[1],pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])
sets={}
for p in sorted(raw.glob("*.txt")):
 vals={x.strip().lower().rstrip(".") for x in p.read_text(errors="replace").splitlines() if x.strip()}
 vals={x for x in vals if x==domain or x.endswith("."+domain)}
 sets[p.stem]=vals
union=set().union(*sets.values()) if sets else set();freq={x:sum(x in s for s in sets.values()) for x in union}
tools=[]
for name,vals in sets.items():
 unique=sum(freq[x]==1 for x in vals);overlap=len(vals)-unique
 tools.append({"tool":name,"count":len(vals),"unique_contribution":unique,"overlap_with_other_tools":overlap,"coverage_percent_of_union":round(100*len(vals)/len(union),2) if union else 0,"redundancy_percent":round(100*overlap/len(vals),2) if vals else 0})
pairs=[];names=sorted(sets)
for i,a in enumerate(names):
 for b in names[i+1:]:
  inter=len(sets[a]&sets[b]);pairs.append({"a":a,"b":b,"intersection":inter,"a_contained_in_b_percent":round(100*inter/len(sets[a]),2) if sets[a] else 0,"b_contained_in_a_percent":round(100*inter/len(sets[b]),2) if sets[b] else 0})
data={"domain":domain,"total_unique":len(union),"tools":tools,"pairs":pairs}
jout.write_text(json.dumps(data,indent=2)+"\n")
lines=[f"domain={domain} total_unique={len(union)}","",f"{'TOOL':18} {'COUNT':>8} {'UNIQUE':>8} {'OVERLAP':>8} {'REDUNDANCY%':>12}"]
for x in tools:lines.append(f"{x['tool']:18} {x['count']:8} {x['unique_contribution']:8} {x['overlap_with_other_tools']:8} {x['redundancy_percent']:12.2f}")
tout.write_text("\n".join(lines)+"\n")
PY
  record_status compare-local success 0 "$(count_lines "$compare/report.txt")"; SUCCESS_COUNT=$((SUCCESS_COUNT+1))
  if [[ "$DRY_RUN" -eq 1 ]]; then : >"$compare/reconcompare.json"; : >"$compare/reconcompare.txt"; record_status reconcompare planned 0 0; return; fi
  if ! have reconcompare; then warn "reconcompare skipped: missing"; record_status reconcompare skipped 0 0; return; fi
  local compare_tmp rawlog rawtxt rawjson
  local ingested=0 expected=0 ingest_failed=0 tool_name report_ok=0 log_rc=1 txt_rc=1 json_rc=1
  compare_tmp="$(mktemp -d "$RUN_TMP_ROOT/reconcompare.XXXXXX")"
  rawlog="$compare_tmp/reconcompare.log"; rawtxt="$compare_tmp/reconcompare.txt"; rawjson="$compare_tmp/reconcompare.json"
  : >"$rawlog"
  for file in "$raw"/*.txt; do
    [[ -s "$file" ]] || continue
    tool_name="$(basename "$file" .txt)"; expected=$((expected+1))
    record_command reconcompare ingest --run "$run_id" --domain "$domain" --tool "$tool_name" --file "$file"
    if run_tracked reconcompare ingest --run "$run_id" --domain "$domain" --tool "$tool_name" --file "$file" >>"$rawlog" 2>&1; then
      ingested=$((ingested+1)); record_status "reconcompare-ingest:$tool_name" success 0 "$(count_lines "$file")"
    else
      ingest_failed=$((ingest_failed+1)); record_status "reconcompare-ingest:$tool_name" failed 0 0
    fi
  done
  if (( expected > 0 && ingest_failed == 0 )) && run_tracked reconcompare report --run "$run_id" >"$rawtxt" 2>>"$rawlog" && run_tracked reconcompare report --run "$run_id" --json >"$rawjson" 2>>"$rawlog"; then
    report_ok=1
  fi
  if redact_file "$rawlog" "$LOG_DIR/reconcompare.log"; then log_rc=0; else log_rc=$?; fi
  if [[ "$report_ok" -eq 1 ]]; then
    if redact_file "$rawtxt" "$compare/reconcompare.txt"; then txt_rc=0; else txt_rc=$?; fi
    if redact_file "$rawjson" "$compare/reconcompare.json"; then json_rc=0; else json_rc=$?; fi
  fi
  rm -rf -- "$compare_tmp"
  if [[ "$report_ok" -eq 1 && "$log_rc" -eq 0 && "$txt_rc" -eq 0 && "$json_rc" -eq 0 ]]; then
    record_status reconcompare success 0 "$ingested"; SUCCESS_COUNT=$((SUCCESS_COUNT+1))
  else
    warn "ReconCompare partial/unavailable; local differential report remains valid"
    : >"$compare/reconcompare.txt"; : >"$compare/reconcompare.json"
    record_status reconcompare degraded 0 "$ingested"
  fi
}

run_dns() {
  local input="$OUT_DIR/subdomains/all.txt" output="$OUT_DIR/dns/resolved.txt" before_failures="$FAILED_COUNT"
  if have puredns || [[ "$DRY_RUN" -eq 1 ]]; then
    build_puredns_cmd "$input"; run_stdout_tool dns-puredns puredns "$output" "${CMD[@]}"
  else
    : >"$output"
  fi
  if [[ "$DRY_RUN" -eq 0 && ! -s "$output" ]]; then
    warn "PureDNS unavailable/empty; using DNSX fallback"
    build_dnsx_cmd "$input"; run_stdout_tool dns-dnsx dnsx "$output" "${CMD[@]}"
    if [[ -s "$output" ]]; then
      FAILED_COUNT="$before_failures"
      record_status dns recovered 0 "$(count_lines "$output")"
    elif [[ "$FAILED_COUNT" -eq "$before_failures" ]]; then
      warn "dns failed: no resolver produced validated hosts"
      record_status dns failed 0 0; FAILED_COUNT=$((FAILED_COUNT+1))
    fi
  fi
}

extract_http() {
  rm -f -- "$OUT_DIR/http/.validated"
  python3 - "$OUT_DIR/http/http.jsonl" "$OUT_DIR/http/web-urls.txt" "$OUT_DIR/http/.validated" <<'PY'
import json,pathlib,sys
src,dst,marker=map(pathlib.Path,sys.argv[1:]);urls=set();bad=0
if src.is_file():
 for number,line in enumerate(src.read_text(errors="strict").splitlines(),1):
  if not line.strip(): continue
  try:o=json.loads(line)
  except json.JSONDecodeError:
   bad+=1;continue
  if not isinstance(o,dict):bad+=1;continue
  u=o.get("url") or o.get("final_url")
  if not isinstance(u,str) or not u.startswith(("http://","https://")):
   bad+=1;continue
  urls.add(u)
if bad: raise SystemExit(3)
tmp=dst.with_name(dst.name+".tmp");tmp.write_text("".join(x+"\n" for x in sorted(urls)));tmp.replace(dst)
marker.write_text("ok\n")
PY
}

run_alive() {
  if [[ "$DRY_RUN" -eq 0 && ! -s "$OUT_DIR/dns/resolved.txt" ]]; then
    : >"$OUT_DIR/http/http.jsonl"; : >"$OUT_DIR/http/web-urls.txt"; rm -f -- "$OUT_DIR/http/.validated"
    warn "alive blocked: DNS produced no input"; record_status httpx blocked 0 0; return
  fi
  build_httpx_cmd "$OUT_DIR/dns/resolved.txt"; run_stdout_tool httpx httpx "$OUT_DIR/http/http.jsonl" "${CMD[@]}"
  set +e; extract_http; local parse_rc=$?; set -e
  if [[ "$parse_rc" -ne 0 ]]; then
    : >"$OUT_DIR/http/web-urls.txt"; rm -f -- "$OUT_DIR/http/.validated"
    warn "httpx parse failed: malformed JSONL contract"; record_status httpx-parse failed 0 0; FAILED_COUNT=$((FAILED_COUNT+1))
  fi
}

run_archives() {
  local domain="$1" raw="$OUT_DIR/urls/raw" tool outfile before_success="$TOOL_SUCCESS_COUNT"
  for tool in "${ARCHIVE_TOOLS[@]}"; do
    outfile="$raw/$tool.txt"
    case "$tool" in
      gau) build_gau_cmd "$domain"; run_stdout_tool gau gau "$outfile" "${CMD[@]}" ;;
      waybackurls) build_waybackurls_cmd "$domain"; run_stdout_tool waybackurls waybackurls "$outfile" "${CMD[@]}" ;;
      waymore)
        build_waymore_cmd "$domain" "$outfile"
        record_command "${CMD[@]}"; printf '[%02d] waymore\n' "$STEP_NUMBER"; STEP_NUMBER=$((STEP_NUMBER+1))
        if [[ "$DRY_RUN" -eq 1 ]]; then : >"$outfile"; record_status waymore planned 0 0
        elif ! have waymore; then : >"$outfile"; warn "waymore skipped: missing"; record_status waymore skipped 0 0
        else
          local waymore_tmp temp rawout rawerr rc red_out red_err red_artifact=1
          waymore_tmp="$(mktemp -d "$RUN_TMP_ROOT/waymore.XXXXXX")"; temp="$waymore_tmp/result.txt"; rawout="$waymore_tmp/stdout"; rawerr="$waymore_tmp/stderr"
          build_waymore_cmd "$domain" "$temp"; set +e
          run_tracked "${CMD[@]}" >"$rawout" 2>"$rawerr"; rc=$?
          redact_file "$rawout" "$LOG_DIR/waymore.stdout.log"; red_out=$?
          redact_file "$rawerr" "$LOG_DIR/waymore.stderr.log"; red_err=$?
          if [[ "$rc" -eq 0 && -f "$temp" ]]; then redact_file "$temp" "$outfile"; red_artifact=$?; fi
          set -e
          if [[ "$rc" -eq 0 && "$red_out" -eq 0 && "$red_err" -eq 0 && "$red_artifact" -eq 0 ]]; then
            record_status waymore success 0 "$(count_lines "$outfile")"
            SUCCESS_COUNT=$((SUCCESS_COUNT+1)); TOOL_SUCCESS_COUNT=$((TOOL_SUCCESS_COUNT+1))
          else
            : >"$outfile"; warn "waymore failed: scanner=$rc capture=$red_out/$red_err artifact=$red_artifact"
            record_status waymore failed 0 0; FAILED_COUNT=$((FAILED_COUNT+1))
          fi
          rm -rf -- "$waymore_tmp"
        fi ;;
    esac
  done
  if [[ "$DRY_RUN" -eq 0 && "$TOOL_SUCCESS_COUNT" -eq "$before_success" ]]; then
    warn "archives failed: no selected archive collector completed"
    record_status archives failed 0 0; FAILED_COUNT=$((FAILED_COUNT+1))
  fi
}

run_crawl() {
  if [[ "$DRY_RUN" -eq 0 && ! -s "$OUT_DIR/http/web-urls.txt" ]]; then
    : >"$OUT_DIR/crawl/katana.txt"; warn "crawl blocked: no responsive URLs"; record_status katana blocked 0 0; return
  fi
  build_katana_cmd "$OUT_DIR/http/web-urls.txt"; run_stdout_tool katana katana "$OUT_DIR/crawl/katana.txt" "${CMD[@]}"
}

run_url_analysis() {
  local domain="$1" files=("$OUT_DIR/urls/raw"/*.txt "$OUT_DIR/crawl/katana.txt")
  normalize_urls "$domain" "$OUT_DIR/urls/all.txt" "${files[@]}"
  python3 - "$OUT_DIR/urls/all.txt" "$OUT_DIR/urls/classified" <<'PY'
import pathlib,re,sys
src,dst=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]);dst.mkdir(parents=True,exist_ok=True)
patterns={"javascript":r"\.js(?:\?|$)","api":r"/(?:api|rest|v[0-9]+|graphql|gql)(?:/|\?|$)|\.(?:json|xml)(?:\?|$)","auth":r"login|signin|signup|oauth|saml|oidc|callback|reset|password|token","uploads":r"upload|attachment|document|avatar|media|download","admin":r"/(?:admin|internal|debug|manage|console|staging|dev)(?:/|\?|$)","openapi":r"swagger|openapi|api-docs|redoc|graphiql|playground","parameters":r"\?[^#]*="}
lines=src.read_text(errors="replace").splitlines() if src.is_file() else []
for name,pat in patterns.items():(dst/f"{name}.txt").write_text("".join(x+"\n" for x in sorted({x for x in lines if re.search(pat,x,re.I)})))
PY
  record_status url-analysis success 0 "$(count_lines "$OUT_DIR/urls/all.txt")"; SUCCESS_COUNT=$((SUCCESS_COUNT+1))
}

run_kaeferjaeger() {
  local domain="$1" output="$OUT_DIR/cloud/kaeferjaeger/sni-associations.txt"
  local stdout_log="$LOG_DIR/kaeferjaeger.stdout.log" stderr_log="$LOG_DIR/kaeferjaeger.stderr.log"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    build_kaeferjaeger_cmd "$domain" "$output"; record_command "${CMD[@]}"; : >"$output"
    record_status kaeferjaeger planned 0 0; return
  fi
  if [[ ! -f "$KAEFERJAEGER_DIR/originiphunter.py" ]]; then
    : >"$output"; warn "kaeferjaeger skipped: script missing"; record_status kaeferjaeger skipped 0 0; return
  fi
  local tempdir temp_output rawout rawerr rc redact_out_rc redact_err_rc validate_rc=1 artifact_rc=1
  tempdir="$(mktemp -d "$RUN_TMP_ROOT/kaeferjaeger.XXXXXX")"; temp_output="$tempdir/result.txt"; rawout="$tempdir/stdout"; rawerr="$tempdir/stderr"
  build_kaeferjaeger_cmd "$domain" "$temp_output"; record_command "${CMD[@]}"
  set +e
  run_tracked "${CMD[@]}" >"$rawout" 2>"$rawerr"; rc=$?
  redact_file "$rawout" "$stdout_log"; redact_out_rc=$?
  redact_file "$rawerr" "$stderr_log"; redact_err_rc=$?
  if [[ "$rc" -eq 0 && -f "$temp_output" ]]; then
    python3 - "$temp_output" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); data=p.read_bytes()
if b"\x00" in data: raise SystemExit(2)
data.decode("utf-8")
PY
    validate_rc=$?
  fi
  if [[ "$rc" -eq 0 && "$validate_rc" -eq 0 ]]; then redact_file "$temp_output" "$output"; artifact_rc=$?; fi
  set -e
  if [[ "$rc" -eq 0 && "$redact_out_rc" -eq 0 && "$redact_err_rc" -eq 0 && "$validate_rc" -eq 0 && "$artifact_rc" -eq 0 ]]; then
    record_status kaeferjaeger success 0 "$(count_lines "$output")"
    SUCCESS_COUNT=$((SUCCESS_COUNT+1)); TOOL_SUCCESS_COUNT=$((TOOL_SUCCESS_COUNT+1))
  else
    : >"$output"; warn "kaeferjaeger failed: scanner=$rc capture=$redact_out_rc/$redact_err_rc artifact=$validate_rc/$artifact_rc"
    record_status kaeferjaeger failed 0 0; FAILED_COUNT=$((FAILED_COUNT+1))
  fi
  rm -rf -- "$tempdir"
}

run_cloud() {
  local domain="$1" tool before_success="$TOOL_SUCCESS_COUNT"
  for tool in "${CLOUD_TOOLS[@]}"; do
    case "$tool" in
      bbot-cloud)
        local dir="$OUT_DIR/cloud/bbot" temp="$RUN_TMP_ROOT/bbot-cloud-output"; build_bbot_cloud_cmd "$domain" "$temp"; record_command "${CMD[@]}"
        if [[ "$DRY_RUN" -eq 1 ]]; then
          mkdir -p -- "$dir"; record_status bbot-cloud planned 0 0
        elif ! have bbot; then
          warn "bbot-cloud skipped: bbot missing"; record_status bbot-cloud skipped 0 0
        else
          local cloud_tmp cloud_out cloud_err rc red_out red_err red_tree=1
          cloud_tmp="$(mktemp -d "$RUN_TMP_ROOT/bbot-cloud.XXXXXX")"; cloud_out="$cloud_tmp/stdout"; cloud_err="$cloud_tmp/stderr"
          rm -rf -- "$temp"; set +e
          run_tracked "${CMD[@]}" >"$cloud_out" 2>"$cloud_err"; rc=$?
          redact_file "$cloud_out" "$LOG_DIR/bbot-cloud.stdout.log"; red_out=$?
          redact_file "$cloud_err" "$LOG_DIR/bbot-cloud.stderr.log"; red_err=$?
          if [[ "$rc" -eq 0 && -d "$temp" ]]; then redact_tree "$temp"; red_tree=$?; fi
          set -e
          if [[ "$rc" -eq 0 && "$red_out" -eq 0 && "$red_err" -eq 0 && "$red_tree" -eq 0 && -d "$temp" ]]; then
            rm -rf -- "$dir"; mv -- "$temp" "$dir"; record_status bbot-cloud success 0 1
            SUCCESS_COUNT=$((SUCCESS_COUNT+1)); TOOL_SUCCESS_COUNT=$((TOOL_SUCCESS_COUNT+1))
          else
            rm -rf -- "$temp"; warn "bbot-cloud failed: scanner=$rc capture=$red_out/$red_err artifact-redaction=$red_tree"
            record_status bbot-cloud failed 0 0; FAILED_COUNT=$((FAILED_COUNT+1))
          fi
          rm -rf -- "$cloud_tmp"
        fi ;;
      kaeferjaeger)
        run_kaeferjaeger "$domain" ;;
    esac
  done
  if [[ "$DRY_RUN" -eq 0 && "$TOOL_SUCCESS_COUNT" -eq "$before_success" ]]; then
    warn "cloud failed: no selected cloud collector completed"
    record_status cloud failed 0 0; FAILED_COUNT=$((FAILED_COUNT+1))
  fi
}

run_stack() {
  if [[ "$DRY_RUN" -eq 0 && ( ! -f "$OUT_DIR/http/.validated" || ! -s "$OUT_DIR/http/http.jsonl" ) ]]; then
    : >"$OUT_DIR/stack/technologies.txt"; : >"$OUT_DIR/stack/services.jsonl"
    warn "stack blocked: no HTTP inventory"; record_status stack blocked 0 0; return
  fi
  python3 - "$OUT_DIR/http/http.jsonl" "$OUT_DIR/stack" <<'PY'
import json,pathlib,sys
src,dst=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]);dst.mkdir(parents=True,exist_ok=True);tech=set();rows=[]
if src.is_file():
 for line in src.read_text(errors="replace").splitlines():
  try:o=json.loads(line)
  except:continue
  found=o.get("tech") or o.get("technologies") or []
  if isinstance(found,str):found=[found]
  tech.update(str(x) for x in found)
  rows.append({k:o.get(k) for k in ("url","status_code","title","webserver","content_type","host","ip","cname") if o.get(k) is not None})
(dst/"technologies.txt").write_text("".join(x+"\n" for x in sorted(tech,key=str.lower)))
(dst/"services.jsonl").write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in rows))
PY
  record_status stack success 0 "$(count_lines "$OUT_DIR/stack/technologies.txt")"; SUCCESS_COUNT=$((SUCCESS_COUNT+1))
}

run_ports() {
  if [[ "$DRY_RUN" -eq 0 && ! -s "$OUT_DIR/dns/resolved.txt" ]]; then : >"$OUT_DIR/ports/naabu.txt"; record_status naabu blocked 0 0; return; fi
  build_naabu_cmd "$OUT_DIR/dns/resolved.txt"; run_stdout_tool naabu naabu "$OUT_DIR/ports/naabu.txt" "${CMD[@]}"
}
run_nuclei() {
  if [[ "$DRY_RUN" -eq 0 && ! -s "$OUT_DIR/http/web-urls.txt" ]]; then : >"$OUT_DIR/nuclei/findings.jsonl"; record_status nuclei blocked 0 0; return; fi
  build_nuclei_cmd "$OUT_DIR/http/web-urls.txt"; run_stdout_tool nuclei nuclei "$OUT_DIR/nuclei/findings.jsonl" "${CMD[@]}"
}

write_summary() {
  local domain="$1"
  python3 - "$domain" "$OUT_DIR" "$STATUS_FILE" "$STAGES_CSV" <<'PY'
import json,pathlib,sys
domain,out,status_file,stages=sys.argv[1],pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]),sys.argv[4].split(",")
def count(p):
 try:return sum(bool(x.strip()) for x in pathlib.Path(p).read_text(errors="replace").splitlines())
 except FileNotFoundError:return 0
status=[]
for line in status_file.read_text(errors="replace").splitlines():
 name,state,duration,items=line.split("\t");status.append({"name":name,"status":state,"duration_seconds":int(duration),"items":int(items)})
data={"domain":domain,"ordered_stages":stages,"status":status,"counts":{"subdomains":count(out/"subdomains/all.txt"),"resolved":count(out/"dns/resolved.txt"),"alive_web":count(out/"http/web-urls.txt"),"urls":count(out/"urls/all.txt"),"api_urls":count(out/"urls/classified/api.txt"),"javascript":count(out/"urls/classified/javascript.txt"),"technologies":count(out/"stack/technologies.txt"),"ports":count(out/"ports/naabu.txt"),"nuclei_leads":count(out/"nuclei/findings.jsonl")},"notice":"Recon output is evidence for investigation, not a verified vulnerability."}
(out/"summary.json").write_text(json.dumps(data,indent=2)+"\n")
lines=[f"Quality Recon: {domain}",f"Stages: {' -> '.join(stages)}"]+[f"{k}: {v}" for k,v in data["counts"].items()]
(out/"summary.txt").write_text("\n".join(lines)+"\n");print("\n"+"\n".join(lines))
PY
}

publish_latest() {
  local base="$1" run_dir="$2" temp="$base/.latest.$$"
  trap '' INT TERM
  rm -f -- "$temp"; ln -s -- "runs/$(basename -- "$run_dir")" "$temp"; mv -Tf -- "$temp" "$base/latest"
  RUN_PUBLISHED=1
  arm_signal_traps
}

process_domain() {
  local domain="$1" base="$OUTPUT_ROOT/$1" stage
  trap '' INT TERM
  RUN_PUBLISHED=0
  RUN_DIR=""
  RUN_TMP_ROOT=""
  arm_signal_traps
  if [[ "$DRY_RUN" -eq 1 ]]; then
    RUN_ID="dry-run"; RUN_DIR="$base/dry-run"; rm -rf -- "$RUN_DIR"; mkdir -p -- "$RUN_DIR"
  else
    mkdir -p -- "$base/runs"
    RUN_ID="$(date -u +%Y%m%dT%H%M%S%NZ)-$$-$RANDOM"; RUN_DIR="$base/runs/$RUN_ID"
    mkdir -- "$RUN_DIR" || die "Run directory collision: $RUN_DIR"
  fi
  OUT_DIR="$RUN_DIR/outputs"; LOG_DIR="$RUN_DIR/logs"; STATUS_FILE="$LOG_DIR/status.tsv"; RUN_TMP_ROOT="$RUN_DIR/.tmp"
  mkdir -p -- "$OUT_DIR"/{subdomains/raw,subdomains/scoped,dns,http,urls/raw,urls/classified,crawl,compare,cloud/bbot,cloud/kaeferjaeger,stack,ports,nuclei} "$LOG_DIR" "$RUN_TMP_ROOT"
  : >"$LOG_DIR/commands.log"; : >"$STATUS_FILE"; STEP_NUMBER=1; SUCCESS_COUNT=0; TOOL_SUCCESS_COUNT=0; FAILED_COUNT=0
  printf '\n=== Quality Recon %s ===\nTarget: %s\nOrder: %s\nRun: %s\n' "$VERSION" "$domain" "$STAGES_CSV" "$RUN_ID"
  for stage in "${STAGES[@]}"; do
    case "$stage" in
      subdomains) run_subdomains "$domain" ;;
      compare) run_compare "$domain" ;;
      dns) run_dns ;;
      alive) run_alive ;;
      archives) run_archives "$domain" ;;
      crawl) run_crawl ;;
      url-analysis) run_url_analysis "$domain" ;;
      cloud) run_cloud "$domain" ;;
      stack) run_stack ;;
      ports) run_ports ;;
      nuclei) run_nuclei ;;
    esac
  done
  write_summary "$domain"; rm -rf -- "$RUN_TMP_ROOT"
  if (( FAILED_COUNT > 0 )); then DOMAIN_RC=2
  elif (( TOOL_SUCCESS_COUNT == 0 && DRY_RUN == 0 )); then DOMAIN_RC=3
  else DOMAIN_RC=0
  fi
  python3 - "$RUN_DIR/completed.json" "$DOMAIN_RC" "$STAGES_CSV" "$SUBDOMAIN_TOOLS_CSV" "$ARCHIVE_TOOLS_CSV" "$CLOUD_TOOLS_CSV" <<'PY'
import json,pathlib,sys
path,rc,stages,subs,archives,cloud=sys.argv[1:]
pathlib.Path(path).write_text(json.dumps({"state":"success" if rc=="0" else "partial","exit_code":int(rc),"stages":stages.split(","),"subdomain_tools":subs.split(","),"archive_tools":archives.split(","),"cloud_tools":cloud.split(",")},indent=2)+"\n")
PY
  [[ "$DRY_RUN" -eq 1 ]] || publish_latest "$base" "$RUN_DIR"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) need_value "$@"; DOMAIN="$2"; shift 2;;
    -l|--list) need_value "$@"; LIST_FILE="$2"; shift 2;;
    --output-root) need_value "$@"; OUTPUT_ROOT="$2"; shift 2;;
    --stages) need_value "$@"; STAGES_CSV="$2"; shift 2;;
    --subdomain-tools) need_value "$@"; SUBDOMAIN_TOOLS_CSV="$2"; shift 2;;
    --archive-tools) need_value "$@"; ARCHIVE_TOOLS_CSV="$2"; shift 2;;
    --cloud-tools) need_value "$@"; CLOUD_TOOLS_CSV="$2"; shift 2;;
    --rate) need_value "$@"; RATE="$2"; shift 2;;
    --dns-rate) need_value "$@"; DNS_RATE="$2"; shift 2;;
    --port-rate) need_value "$@"; PORT_RATE="$2"; shift 2;;
    --crawl-depth) need_value "$@"; CRAWL_DEPTH="$2"; shift 2;;
    --resolvers) need_value "$@"; RESOLVERS_FILE="$2"; shift 2;;
    --deep) DEEP=1; shift;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage; exit 0;;
    --version) printf '%s\n' "$VERSION"; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done

[[ -n "$DOMAIN" || -n "$LIST_FILE" ]] || die "Use --domain or --list"
[[ -z "$DOMAIN" || -z "$LIST_FILE" ]] || die "Use only one of --domain or --list"
if [[ -z "$RESOLVERS_FILE" && -f "$DEFAULT_RESOLVERS_FILE" ]]; then RESOLVERS_FILE="$DEFAULT_RESOLVERS_FILE"; fi
[[ "$RATE" =~ ^([1-9]|10)$ ]] || die "--rate must be 1 through 10"
[[ "$DNS_RATE" =~ ^([1-9]|[1-9][0-9]|[1-4][0-9]{2}|500)$ ]] || die "--dns-rate must be 1 through 500"
[[ "$PORT_RATE" =~ ^([1-9]|[1-9][0-9]|[1-9][0-9]{2}|1000)$ ]] || die "--port-rate must be 1 through 1000"
[[ "$CRAWL_DEPTH" =~ ^[1-3]$ ]] || die "--crawl-depth must be 1 through 3"
[[ -z "$LIST_FILE" || -f "$LIST_FILE" ]] || die "Domain list not found: $LIST_FILE"
[[ -z "$RESOLVERS_FILE" || -f "$RESOLVERS_FILE" ]] || die "Resolver list not found: $RESOLVERS_FILE"
[[ "$OUTPUT_ROOT" != -* && "$OUTPUT_ROOT" != *$'\n'* ]] || die "Invalid --output-root"
have setsid || die "Required process-group utility missing: setsid"
if [[ "$DEEP" -eq 1 ]]; then
  [[ ",$STAGES_CSV," == *,ports,* ]] || STAGES_CSV="${STAGES_CSV},ports"
  [[ ",$STAGES_CSV," == *,nuclei,* ]] || STAGES_CSV="${STAGES_CSV},nuclei"
fi
parse_lists; validate_lists; validate_stage_dependencies

TMP_ROOT="$(mktemp -d)"
trap cleanup_tmp EXIT
arm_signal_traps
TMP_DOMAINS="$TMP_ROOT/domains"; TMP_VALID="$TMP_ROOT/valid"
if [[ -n "$DOMAIN" ]]; then printf '%s\n' "$DOMAIN" >"$TMP_DOMAINS"; validate_domains "$TMP_DOMAINS" "$TMP_VALID" 0 || die "Invalid domain input"; else cp -- "$LIST_FILE" "$TMP_DOMAINS"; validate_domains "$TMP_DOMAINS" "$TMP_VALID" 1 || die "Invalid domain input"; fi
mapfile -t DOMAINS <"$TMP_VALID"; [[ ${#DOMAINS[@]} -gt 0 ]] || die "No valid domains supplied"
mkdir -p -- "$OUTPUT_ROOT"; FINAL_RC=0
for domain in "${DOMAINS[@]}"; do process_domain "$domain"; if (( DOMAIN_RC > FINAL_RC )); then FINAL_RC=$DOMAIN_RC; fi; done
exit "$FINAL_RC"

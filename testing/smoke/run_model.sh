#!/usr/bin/env bash
# OTA-Shield — tofino-model smoke test driver.
#
# Launches tofino-model + bf_switchd against the compiled pipeline, runs the
# PTF smoke test suite, then tears everything down. Used by CI and developer
# iteration. Phase 1 target: test_passthrough.py passes.

set -euo pipefail

P4_PROG="${1:-ota_shield}"
SDE="${SDE:-/opt/bf-sde-9.13.2}"
SDE_INSTALL="${SDE_INSTALL:-$SDE/install}"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_DIR="$PROJECT_ROOT/testing/smoke"
OUTDIR="$SDE_INSTALL/share/tofinopd/$P4_PROG"

# ---------- sanity checks ----------
if [[ ! -d "$OUTDIR" ]]; then
    echo "ERROR: $OUTDIR not found. Run 'make build' first."
    exit 1
fi

if [[ ! -x "$SDE/run_tofino_model.sh" ]]; then
    echo "ERROR: $SDE/run_tofino_model.sh not found."
    echo "Set SDE env var to the BF-SDE root, or install BF-SDE."
    exit 1
fi

LOG_DIR="$(mktemp -d /tmp/ota-shield-smoke-XXXXXX)"
echo "Smoke logs: $LOG_DIR"

cleanup() {
    set +e
    [[ -n "${MODEL_PID:-}" ]] && kill "$MODEL_PID" 2>/dev/null
    [[ -n "${SWITCHD_PID:-}" ]] && kill "$SWITCHD_PID" 2>/dev/null
    wait 2>/dev/null
    echo "Logs preserved in: $LOG_DIR"
}
trap cleanup EXIT

# ---------- launch tofino-model ----------
echo "[smoke] Starting tofino-model..."
"$SDE/run_tofino_model.sh" -p "$P4_PROG" >"$LOG_DIR/model.log" 2>&1 &
MODEL_PID=$!
sleep 3

# ---------- launch bf_switchd against model ----------
echo "[smoke] Starting bf_switchd against model..."
"$SDE/run_switchd.sh" -p "$P4_PROG" --model >"$LOG_DIR/switchd.log" 2>&1 &
SWITCHD_PID=$!
sleep 10

# ---------- run PTF tests ----------
echo "[smoke] Running PTF tests from $TEST_DIR..."
if "$SDE/run_p4_tests.sh" -p "$P4_PROG" -t "$TEST_DIR" >"$LOG_DIR/ptf.log" 2>&1; then
    echo "[smoke] PASS"
    RESULT=0
else
    echo "[smoke] FAIL — see $LOG_DIR/ptf.log"
    tail -60 "$LOG_DIR/ptf.log"
    RESULT=1
fi

exit "$RESULT"

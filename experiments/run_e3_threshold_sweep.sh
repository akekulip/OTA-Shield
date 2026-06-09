#!/usr/bin/env bash
# E3 — R5 threshold sweep. Recompiles the P4 pipeline for each candidate
# threshold, restarts bf_switchd + controller, runs E1 trials, archives.
#
# Honest measurement: no hardcoded numbers. All results land in
# runs/experiments/E3_T<value>/ and the aggregator picks them up.
#
# Usage:
#   ./run_e3_threshold_sweep.sh [thresholds...] [--trials N]
# Default thresholds: 2 3 4 5 6 8 10
# Default trials: 5
#
# REQUIRES manual confirmation between thresholds because each compile +
# bf_switchd restart needs human-in-the-loop on the switch side. This
# script is a CHECKLIST that prints exactly the commands to run on the
# switch for each threshold; it does not bypass restart safety rules.

set -euo pipefail

THRESHOLDS=()
TRIALS=5
while [[ $# -gt 0 ]]; do
    case "$1" in
        --trials) TRIALS="$2"; shift 2 ;;
        *) THRESHOLDS+=("$1"); shift ;;
    esac
done
[[ ${#THRESHOLDS[@]} -eq 0 ]] && THRESHOLDS=(2 3 4 5 6 8 10)

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
P4_FILE="$REPO_ROOT/p4src/fleet_monitor.p4"
SWITCH=${SWITCH:-decps@10.10.54.15}
SWITCH_DIR=${SWITCH_DIR:-/home/decps/my_program/ota}

# m13: restore the pristine P4 file even if the user Ctrl-C's mid-sweep.
cp "$P4_FILE" "$P4_FILE.pristine"
restore_p4() {
    if [[ -f "$P4_FILE.pristine" ]]; then
        mv "$P4_FILE.pristine" "$P4_FILE"
        echo "[trap] Restored $P4_FILE to pre-sweep state."
    fi
}
trap restore_p4 EXIT

echo "==================================================================="
echo "E3 R5-threshold sweep"
echo "  thresholds : ${THRESHOLDS[*]}"
echo "  trials/each: $TRIALS"
echo "  P4 source  : $P4_FILE"
echo "  switch     : $SWITCH"
echo "==================================================================="

for T in "${THRESHOLDS[@]}"; do
    echo
    echo "------------------ THRESHOLD T=$T -------------------------------"

    # M1 FIX (code review). Patch BOTH:
    #   (1) the R5_THRESHOLD_CONST line, and
    #   (2) the range-match table entry in the SAME file (lower bound = T+1).
    # Otherwise the firing threshold stays at the original const while the
    # diagnostic value changes — every E3 data point would be measured at
    # the same actual threshold, invalidating the F1-vs-T figure.
    LOWER=$((T + 1))
    sed -i.bak -E \
        -e "s/const bit<16> R5_THRESHOLD_CONST = 16w[0-9]+;/const bit<16> R5_THRESHOLD_CONST = 16w$T;/" \
        -e "s/\(16w[0-9]+ \.\. 16w0xFFFF\) : set_r5_fired\(\);/(16w$LOWER .. 16w0xFFFF) : set_r5_fired();/" \
        "$P4_FILE"
    grep -E "R5_THRESHOLD_CONST|set_r5_fired" "$P4_FILE" | head -3

    # Push to switch and recompile.
    scp -q "$P4_FILE" "$SWITCH:$SWITCH_DIR/p4src/"

    echo "[switch] Compiling..."
    ssh "$SWITCH" "cd $SWITCH_DIR && ./ota_shield.sh 2>&1 | tail -20"

    echo
    echo ">>> MANUAL STEPS ON SWITCH (one terminal each) <<<"
    echo ">>> 1) Restart bf_switchd:"
    echo "     ssh $SWITCH"
    echo "     sudo pkill -INT bf_switchd; sleep 5; sudo $SWITCH_DIR/run_switch.sh"
    echo ">>> 2) After 'bfshell>' appears, in bf-sde.pm: re-add ports"
    echo "     pm; port-add 15/0 25G RS; port-add 15/3 25G RS;"
    echo "     port-enb 15/0; port-enb 15/3; show; exit"
    echo ">>> 3) Restart controller in another terminal (your usual env+launch)"
    echo
    read -p "Press ENTER once switch + ports + controller are up, or Ctrl-C to abort..."

    # Run E1 against this threshold.
    echo "[laptop] Running E1 (T=$T) for $TRIALS trials..."
    cd "$REPO_ROOT"
    make -C experiments e1 TRIALS="$TRIALS"
    mv runs/experiments/E1_attack_detection "runs/experiments/E3_T${T}"
    echo "[laptop] Archived to runs/experiments/E3_T${T}"
done

echo
echo "==================================================================="
echo "E3 sweep complete. Aggregating..."
make -C experiments aggregate figures
echo
echo "Per-threshold summaries:"
for T in "${THRESHOLDS[@]}"; do
    p="runs/experiments/_agg/E3_T${T}.json"
    [[ -f "$p" ]] && python3 -c "
import json
d=json.load(open('$p'))
a=d['aggregate']
print(f\"  T=$T  P={a['precision']['mean']:.3f}  R={a['recall']['mean']:.3f}  F1={a['f1']['mean']:.3f}\")"
done

# Trap on EXIT will restore P4_FILE to .pristine.
rm -f "${P4_FILE}.bak"

#!/bin/bash
# OTA-Shield — self-contained build script.
#
# Sets BF-SDE 9.13.2 environment and compiles the P4 pipeline.
# Output: $SDE/build/ota_shield/ota_shield.conf
#
# Usage:
#     ./build_ota_shield.sh
#
# Run from the project root (/home/decps/my_program/ota).

set -e

# ---------- SDE environment ----------
export SDE=${SDE:-/home/decps/Downloads/bf-sde-9.13.2}
export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH

# ---------- Project paths ----------
P4_PROG=ota_shield
PROJECT_DIR=$(cd "$(dirname "$0")" && pwd)
P4SRC_DIR=$PROJECT_DIR/p4src
P4_SRC=$P4SRC_DIR/${P4_PROG}.p4
OUTDIR=$SDE/build/${P4_PROG}

# ---------- Sanity checks ----------
if [[ ! -x "$SDE_INSTALL/bin/bf-p4c" ]]; then
    echo "ERROR: bf-p4c not found at $SDE_INSTALL/bin/bf-p4c"
    echo "Check SDE path: SDE=$SDE"
    exit 1
fi
if [[ ! -f "$P4_SRC" ]]; then
    echo "ERROR: $P4_SRC not found."
    echo "Run this script from the project root."
    exit 1
fi

echo "============================================================"
echo "OTA-Shield build"
echo "============================================================"
echo "SDE         : $SDE"
echo "SDE_INSTALL : $SDE_INSTALL"
echo "bf-p4c      : $(bf-p4c --version)"
echo "Source      : $P4_SRC"
echo "Output dir  : $OUTDIR"
echo "============================================================"
echo ""

mkdir -p "$OUTDIR"

# ---------- Compile ----------
$SDE_INSTALL/bin/bf-p4c \
    --target tofino \
    --arch tna \
    --std p4-16 \
    -I"$P4SRC_DIR" \
    -o "$OUTDIR" \
    "$P4_SRC"

STATUS=$?

if [[ $STATUS -ne 0 ]]; then
    echo ""
    echo "============================================================"
    echo "BUILD FAILED (exit $STATUS)"
    echo "============================================================"
    exit $STATUS
fi

echo ""
echo "============================================================"
echo "BUILD OK"
echo "============================================================"
echo "Conf file   : $OUTDIR/${P4_PROG}.conf"
echo ""

# ---------- Resource report ----------
RESOURCE_LOG=$OUTDIR/pipe/logs/mau.resources.log
if [[ -f "$RESOURCE_LOG" ]]; then
    echo "=== MAU resource utilisation (first 80 lines) ==="
    head -80 "$RESOURCE_LOG"
    echo ""
    echo "Full report: $RESOURCE_LOG"
else
    echo "WARN: resource log not found at $RESOURCE_LOG"
fi

# ---------- Stage summary if available ----------
STAGE_LOG=$OUTDIR/pipe/logs/phv_allocation_summary_pipe.log
if [[ -f "$STAGE_LOG" ]]; then
    echo ""
    echo "=== PHV allocation summary (first 40 lines) ==="
    head -40 "$STAGE_LOG"
fi

echo ""
echo "Next step: start the switch with ./run_switch.sh"

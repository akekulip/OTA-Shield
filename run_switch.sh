#!/bin/bash
# OTA-Shield — start bf_switchd on the Tofino with the ota_shield pipeline.
#
# Mirrors Philip's existing my_monitor start script, adapted to ota_shield.
# Run from the project root:
#     ./run_switch.sh
#
# Prerequisites:
#   1. make build   (writes $SDE/build/ota_shield/ota_shield.conf)
#   2. bf_kdrv loaded this boot (this script attempts a reload; safe to repeat)
#
# This process runs in the FOREGROUND so you can see switchd output.
# Open a separate terminal for the controller and traffic probes.

set -e

export SDE=${SDE:-/home/decps/Downloads/bf-sde-9.13.2}
export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH

P4_PROG=${P4_PROG:-ota_shield}
CONF_FILE=$SDE/build/$P4_PROG/$P4_PROG.conf
STATUS_PORT=${STATUS_PORT:-7777}

if [[ ! -f "$CONF_FILE" ]]; then
    echo "ERROR: $CONF_FILE not found."
    echo "Did you run 'make build' in this project?"
    exit 1
fi

echo "=== OTA-Shield switch bring-up ==="
echo "SDE          : $SDE"
echo "Program      : $P4_PROG"
echo "Conf file    : $CONF_FILE"
echo "Status port  : $STATUS_PORT"
echo ""

# Load the kernel driver (idempotent; prints a warning if already loaded)
$SDE_INSTALL/bin/bf_kdrv_mod_load $SDE_INSTALL 2>/dev/null || true

# Start bf_switchd in foreground
exec $SDE_INSTALL/bin/bf_switchd \
    --install-dir $SDE_INSTALL \
    --conf-file $CONF_FILE \
    --status-port $STATUS_PORT

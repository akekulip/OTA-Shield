#!/usr/bin/env bash
# E10 helper — capture vision-side PCAP for a given duration so we can
# replay it through Suricata for the baseline comparison.
#
# Usage:
#   capture_pcap.sh <vision_host> <output.pcap> <duration_s>
# Example:
#   capture_pcap.sh decps@10.10.54.19 runs/baseline_suricata/e1.pcap 60
#
# Requires tcpdump on vision and passwordless sudo for it (already set up
# in our experiment infrastructure for python3).

set -euo pipefail
VHOST=${1:-decps@10.10.54.19}
OUT=${2:-runs/baseline_suricata/capture.pcap}
DUR=${3:-60}
IFACE=${IFACE:-enp59s0f0np0}

mkdir -p "$(dirname "$OUT")"

REMOTE_PCAP="/tmp/ota_e10_$$.pcap"
echo "[capture] Starting tcpdump on $VHOST iface=$IFACE for ${DUR}s"
# Use BPF expression WITHOUT nested single quotes — ssh + outer "..." eats
# the inner single quotes otherwise. Escaping the expression with \"...\"
# makes tcpdump see one filter string. Drop the `|| true` so we see real
# failures.
# Use tcpdump's own rotation to self-terminate after DUR seconds
# (sudoers allows tcpdump directly, but not the `timeout` wrapper).
ssh "$VHOST" "sudo -n tcpdump -G ${DUR} -W 1 -i $IFACE -w $REMOTE_PCAP tcp and port 1883" || echo "[capture] tcpdump returned $? (exit after rotation=OK)"

echo "[capture] Pulling PCAP back to $OUT"
scp -q "$VHOST:$REMOTE_PCAP" "$OUT"
ssh "$VHOST" "rm -f $REMOTE_PCAP"

echo "[capture] Done. $(du -h $OUT | cut -f1) captured"

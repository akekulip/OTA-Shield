/* OTA-Shield — ota_shield.p4 (top-level TNA program)
 *
 * Pipeline stages:
 *   Ethernet/IPv4/TCP parse + L2 forward + classify digest
 *   MQTT parser + OTA header extraction + PUBLISH digest
 *   OTA topic classifier + session manager + session-finalize digest
 *   R5 fleet monitor (Bloom-gated distinct-BMS counter) + R5 alert digest
 *   R1/R2/R4 secondary rules + HOLD path
 *
 * Target:   Intel Tofino 1 (UfiSpace S9180-32X)
 * SDE:      BF-SDE 9.13.2
 * Compile:  make -C p4build build
 *
 * Authoritative design docs: definitions/*.md, plans/*.md
 */

#include <core.p4>
#include <tna.p4>

#include "headers.p4"
#include "parser.p4"
#include "ingress_control.p4"
#include "deparser.p4"

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;

/* OTA-Shield — policy_engine.p4
 *
 * Combine per-rule fire flags into a single session-level
 * `action_code` that downstream logic (controller override table, HOLD
 * mirror session) can reason over.
 *
 * Mapping (coding_plan.md §6):
 *   R2 fired  -> DROP  (unauthorized source is a hard security boundary)
 *   R1/R4/R5  -> HOLD  (behavioural anomalies — controller arbitrates)
 *   none      -> PASS  (normal traffic)
 *
 * action_code is a bit<8> to stay byte-aligned (Tofino 1 PHV preference).
 *   0 = PASS
 *   1 = HOLD
 *   2 = DROP
 *
 * The controller subscribes to the phase6_hold_digest_t stream and issues
 * short-lived entries into `session_action_override` to realise the HOLD
 * policy (fail-closed 5 s timeout handled controller-side).
 */

#ifndef _OTA_SHIELD_POLICY_ENGINE_P4_
#define _OTA_SHIELD_POLICY_ENGINE_P4_

#include "headers.p4"

const bit<8> ACTION_PASS = 0;
const bit<8> ACTION_HOLD = 1;
const bit<8> ACTION_DROP = 2;

control PolicyEngine(
    inout header_t   hdr,
    inout metadata_t meta)
{
    action set_pass() { meta.action_code = ACTION_PASS; }
    action set_hold() { meta.action_code = ACTION_HOLD; }
    /* RV-4 fix: only an R5 (fleet fanout) HOLD is a coordination/leak
     * signal and arms the per-source hold cascade. R1 (replay), R4
     * (oversize), and R6 (rollback) HOLDs are per-flow behavioural
     * anomalies the arbiter (Gate A/Gate B) handles, so they must NOT
     * arm the cascade — otherwise legitimate re-pushes and authorized
     * rollbacks get dropped at line rate (RV-4). */
    action set_hold_arm() { meta.action_code = ACTION_HOLD; meta.arm_eligible = 1; }
    action set_drop() { meta.action_code = ACTION_DROP; }

    /* Priority: R2 (security) beats R1/R4/R5 (behavioural) beats PASS.
     * Each clause is a byte-wide flag compare — fits the MAU gateway
     * budget without combining with downstream predicates. We keep
     * PolicyEngine.apply() unconditional from ingress_control to prevent
     * bf-p4c from folding guards into these compares. */
    apply {
        if (meta.r2_fired == 1) {
            set_drop();
        } else if (meta.r5_fired == 1) {
            set_hold_arm();   /* fleet-fanout HOLD -> cascade-eligible */
        } else if (meta.r1_fired == 1 ||
                   meta.r4_fired == 1 ||
                   meta.r6_fired == 1) {
            set_hold();       /* replay/oversize/rollback HOLD -> NOT cascade-eligible */
        } else {
            set_pass();
        }
    }
}

#endif /* _OTA_SHIELD_POLICY_ENGINE_P4_ */

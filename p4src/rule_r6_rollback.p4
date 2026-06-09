/* R6: per-BMS firmware version monotonicity.
 * Fires if ota_version_parsed < max_version_seen_for_bms_idx.
 * Routes to HOLD (behavioural), not DROP.
 *
 * Tofino 1 / SDE 9.13.2 constraint: a gateway cannot compare two
 * non-constant PHV fields (4B + 12b PHV input budget; one operand must
 * be constant). The rollback decision therefore lives INSIDE the SALU,
 * which emits an 8-bit fire flag. The caller copies that flag into
 * meta.r6_fired. We don't expose prev_version to the deparser because
 * each SALU can only emit one output value per packet.
 *
 * T1.6 — R6 poisoning fix (MASTER_LEDGER.md, panel-7 02_p4_correctness
 * _fix.md §3). The original single-stage SALU updated the per-BMS max-
 * version register on every OTA packet, which let an unauthorised
 * source (one that fails the R2 authorised-source MAT) poison the
 * register with an arbitrarily large version. A subsequent legitimate
 * update from an authorised source then looked like a rollback and
 * fired R6 spuriously. The fix is a two-stage probe-then-commit:
 *   1. r6_version_probe (read-only): emits the rollback fire flag based
 *      on the *current* stored max, without mutating the register.
 *   2. r6_version_commit (gated write): advances the stored max only
 *      when meta.r2_fired == 0 AND meta.r6_fired == 0, i.e. only an
 *      authorised, non-rollback packet is allowed to advance state.
 * Two RegisterActions on the same register co-stage on Tofino 1 (Spike
 * 5 / 3a-paired). meta.r2_fired is resolved 3 stages upstream by
 * r2_authorized_sources in ingress_control.p4, so it is in metadata
 * when R6 runs. Net stage delta: 0.
 *
 * Security argument: an unauthorised source attempting to poison the
 * per-BMS max-version register first triggers R2 (unauthorised
 * source); when R2 fires, r2_fired = 1, and the commit SALU is gated
 * off, so the malicious version cannot poison the register. A
 * subsequent legitimate update from an authorised source still sees
 * the original max and is correctly classified.
 */

#ifndef _OTA_SHIELD_RULE_R6_ROLLBACK_P4_
#define _OTA_SHIELD_RULE_R6_ROLLBACK_P4_

#include "headers.p4"

control RuleR6Rollback(
    inout header_t   hdr,
    inout metadata_t meta)
{
    /* One 32-bit slot per BMS. Init 0 = never seen; legitimate versions
     * are >= 1 so first-packet never fires. */
    Register<bit<32>, bit<8>>(256, 0) r6_bms_max_version_reg;

    /* Stage 1 — probe: read-only check that emits r=1 if incoming
     * version < stored max. Does NOT mutate the register. Safe to run
     * on every OTA packet, including unauthorised ones. */
    RegisterAction<bit<32>, bit<8>, bit<8>>(r6_bms_max_version_reg)
    r6_version_probe = {
        void apply(inout bit<32> v, out bit<8> r) {
            r = (meta.ota_version_parsed < v) ? 8w1 : 8w0;
        }
    };

    /* Stage 2 — commit: advance the stored max to max(v, incoming) and
     * also emit the rollback flag (same semantics as probe). On Tofino 1
     * with the simplified single-predicate gate (`r2_fired==0`), bf-p4c
     * collapses probe and commit into one SALU table at one stage. Only
     * ONE action runs per packet (selected by r2_fired); its output is
     * assigned to meta.r6_fired. Therefore commit must emit the same
     * rollback flag probe would so that authorised-rollback detection
     * still works for legitimate sources. The internal `>=` clause both
     * advances v non-rollback and inhibits the write on rollback. */
    RegisterAction<bit<32>, bit<8>, bit<8>>(r6_bms_max_version_reg)
    r6_version_commit = {
        void apply(inout bit<32> v, out bit<8> r) {
            if (meta.ota_version_parsed >= v) {
                v = meta.ota_version_parsed;
                r = 0;
            } else {
                r = 1;
            }
        }
    };

    apply {
        if (meta.is_ota == 1 &&
            meta.is_mqtt_publish == 1 &&
            meta.has_ota_hdr == 1 &&
            meta.bms_known == 1)
        {
            meta.r6_fired = r6_version_probe.execute(meta.bms_idx);
            /* Commit gate: only authorized sources may advance the per-BMS
             * max-version. The original compound `r2_fired==0 && r6_fired==0`
             * gate was miscompiled by bf-p4c into an inverted gateway on
             * Tofino 1 (cond-41 mapped 0x0000 to skip-commit, miss to
             * run-commit — verified by direct register inspection: poison
             * trial with the compound gate left register[0] = 0 even for
             * legitimate v=49 follow-ups). The simpler single-predicate
             * gate avoids the inversion. The outer r6_fired==0 check is
             * redundant because the commit SALU already guards the write
             * with its own internal `if (ota_version_parsed >= v)` clause:
             * a rollback attempt by an authorized source (v_packet < v)
             * runs commit but the internal compare prevents the write. */
            if (meta.r2_fired == 0) {
                r6_version_commit.execute(meta.bms_idx);
            }
        }
    }
}

#endif

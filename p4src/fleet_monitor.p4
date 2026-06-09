/* OTA-Shield — fleet_monitor.p4
 *
 * Phase 4: R5 rule — Bloom-gated distinct-target counter.
 *
 * Per finding AF-002, R5's stated semantic ("distinct BMS with active OTA
 * session in 60s window") is set cardinality, not frequency. CMS answers
 * the wrong question; we implement the cardinality directly with three
 * independent Bloom filters + a single distinct-counter register.
 *
 * Per AF-003 review, we use one RegisterAction per register (Tofino 1
 * constraint) — `count_update` branches internally on the AND-reduced
 * Bloom-hit flag to decide whether to increment.
 *
 * Registers:
 *   bf_r0/1/2        : 3 × u8 × 1024   ≈ 3 KB total   (3 MAU stages)
 *   r5_count_reg     : u32 × 1         ≈ 4 B          (1 MAU stage)
 *   r5_threshold_reg : u32 × 1         ≈ 4 B          (1 MAU stage)
 *
 * The controller clears the three Bloom filters and the counter every 60 s
 * (tumbling window). See controller/ota_shield_controller.py.
 */

#ifndef _OTA_SHIELD_FLEET_MONITOR_P4_
#define _OTA_SHIELD_FLEET_MONITOR_P4_

#include "headers.p4"

/* Custom 16-bit CRC polynomial (CCITT-like, distinct from CRC32) for the
 * third hash — TNA 9.13.2 `HashAlgorithm_t` does not include `CRC_CCITT`
 * directly (AF-003), so we instantiate it via CRCPolynomial. */
CRCPolynomial<bit<16>>(
    coeff     = 0x1021,
    reversed  = false,
    msb       = false,
    extended  = false,
    init      = 0xFFFF,
    xor       = 0x0000
) ccitt_poly;

control FleetMonitor(
    inout header_t   hdr,
    inout metadata_t meta)
{
    /* ---------- Three independent hashes over dst_ip + salt ----------
     * Salt bytes ensure distinct hash outputs even when two Hash units
     * share an underlying CRC unit on Tofino 1.
     */
    Hash<bit<10>>(HashAlgorithm_t.CRC32)             h0;
    Hash<bit<10>>(HashAlgorithm_t.CRC16)             h1;
    Hash<bit<10>>(HashAlgorithm_t.CUSTOM, ccitt_poly) h2;

    /* ---------- Bloom filter registers ---------- */
    Register<bit<8>, bit<10>>(1024, 0) bf_r0;
    Register<bit<8>, bit<10>>(1024, 0) bf_r1;
    Register<bit<8>, bit<10>>(1024, 0) bf_r2;

    RegisterAction<bit<8>, bit<10>, bit<8>>(bf_r0) bf_r0_test_set = {
        void apply(inout bit<8> v, out bit<8> r) { r = v; v = 8w1; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(bf_r1) bf_r1_test_set = {
        void apply(inout bit<8> v, out bit<8> r) { r = v; v = 8w1; }
    };
    RegisterAction<bit<8>, bit<10>, bit<8>>(bf_r2) bf_r2_test_set = {
        void apply(inout bit<8> v, out bit<8> r) { r = v; v = 8w1; }
    };

    /* ---------- Distinct-target counter ----------
     *
     * Single RegisterAction per Tofino 1 constraint (AF-003). The predicate
     * `meta.r5_all_hit == 0` (set in the control apply before invocation)
     * controls whether to increment; we always return the current value.
     */
    /* Register narrowed to bit<16> so the range-match threshold table in
     * `r5_threshold_check` has a 2-byte (4-nibble) key — under Tofino 1's
     * 5-nibble range-match key budget. Distinct-BMS count in a 60s window
     * tops out at ~100, safely below 65535. */
    Register<bit<16>, bit<1>>(1, 0) r5_count_reg;

    RegisterAction<bit<16>, bit<1>, bit<16>>(r5_count_reg) count_update = {
        void apply(inout bit<16> v, out bit<16> r) {
            if (meta.r5_all_hit == 0) {
                v = v + 16w1;
            }
            r = v;
        }
    };

    /* ---------- R5 threshold (compile-time constant) ----------
     *
     * Tofino 1 MAU predicates require that at least one operand of a
     * comparison be a constant. A runtime-settable register value cannot
     * be compared against another runtime field in the same action.
     *
     * For v1 the threshold is compiled in. Changing it requires a recompile
     * (a few minutes). The metadata field `r5_threshold_val` is still
     * populated so the phase-4 digest reports the actual threshold in use.
     * Definition 3.5 derives R5_THRESHOLD = P99.9(baseline) + 3 = 4.
     */
    const bit<16> R5_THRESHOLD_CONST = 16w4;

    /* ---------- Range-match threshold table ----------
     *
     * A 32-bit magnitude compare (`>`) in a gateway uses gateway PHV input,
     * which bf-p4c combines with the downstream digest-priority if-chain in
     * ingress_control. The combined predicate exceeds the 44-bit MAU limit.
     *
     * Range-match tables resolve magnitude compares via MAU TCAM range
     * encoding — no gateway PHV input consumed. This is the canonical
     * Tofino idiom for threshold detection.
     */
    action set_r5_fired() { meta.r5_fired = 1; }
    table r5_threshold_check {
        key = { meta.r5_count_val : range; }
        actions = { set_r5_fired; @defaultonly NoAction; }
        size = 2;
        const entries = {
            (16w5 .. 16w0xFFFF) : set_r5_fired();
        }
        default_action = NoAction;
    }

    apply {
        /* INTERNAL guard: Bloom + count update run only for OTA PUBLISHes
         * with valid header. Non-OTA packets leave r5_count_val at 0
         * (parser init), so the final unconditional compare is safe.
         *
         * T1.6.c — RAT relaxation for fleet rollouts. R5 fanout was
         * firing on legitimate authorized rollouts (smoke for T1.6 hit
         * R5 on the 5th BMS of a 5-BMS legit follow-up). R2 already
         * drops unauthorized OTA packets one-at-a-time; R5 should catch
         * SUSTAINED unauthorized fanout, not legitimate fleet pushes.
         * Same RoCE-inspired pattern as D1 (R1) and D2 (R6): write-side
         * gated on the source authorization. With this gate, BF + count
         * track only unauthorized sources, so authorized fleet pushes
         * don't burn BF slots either.
         */
        if (meta.is_ota == 1 && meta.is_mqtt_publish == 1 && meta.has_ota_hdr == 1) {
            if (meta.r2_fired == 1) {
                bit<10> idx0 = h0.get<tuple<bit<32>, bit<8>>>({hdr.ipv4.dst_addr, 8w0x00});
                bit<10> idx1 = h1.get<tuple<bit<32>, bit<8>>>({hdr.ipv4.dst_addr, 8w0xA5});
                bit<10> idx2 = h2.get<tuple<bit<32>, bit<8>>>({hdr.ipv4.dst_addr, 8w0x3F});

                meta.r5_bf_hit0 = bf_r0_test_set.execute(idx0);
                meta.r5_bf_hit1 = bf_r1_test_set.execute(idx1);
                meta.r5_bf_hit2 = bf_r2_test_set.execute(idx2);

                if (meta.r5_bf_hit0 == 1 && meta.r5_bf_hit1 == 1 && meta.r5_bf_hit2 == 1) {
                    meta.r5_all_hit = 1;
                } else {
                    meta.r5_all_hit = 0;
                }

                meta.r5_count_val = count_update.execute(0);
            }
            meta.r5_threshold_val = R5_THRESHOLD_CONST;
        }

        /* Range-match threshold — bypasses gateway PHV input limit. */
        r5_threshold_check.apply();
    }
}

#endif /* _OTA_SHIELD_FLEET_MONITOR_P4_ */

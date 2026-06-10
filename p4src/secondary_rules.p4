/* OTA-Shield — secondary_rules.p4
 *
 * R1 (frequency), R4 (size). R2 is an exact-match table in
 * ingress_control.p4. R3 is controller-side.
 *
 * Tofino 1 MAU compile constraints addressed here:
 *   - Action predicates need one constant operand per compare → R1 and R4
 *     thresholds are compile-time constants.
 *   - Two-runtime-operand subtract is forbidden → the R1 delta
 *     (coarse_time - last_seen) is computed inside the r1_last_seen_reg
 *     stateful ALU, where "register - input" is a native single-stage op.
 *   - "Shift + OR across PHV containers" fails → rule_hits uses concat.
 *
 * Thresholds:
 *   R1_MIN_INTERVAL_SEC = 14400   (4 hours; detects rapid replay A5)
 *   R4_MAX_BYTES        = 2 MB    (Definition 3.8)
 * Change by re-compiling (fast, no runtime write needed).
 */

#ifndef _OTA_SHIELD_SECONDARY_RULES_P4_
#define _OTA_SHIELD_SECONDARY_RULES_P4_

#include "headers.p4"

control SecondaryRules(
    inout header_t   hdr,
    inout metadata_t meta)
{
    /* ---------- Compile-time thresholds ----------
     *
     * Range-match keys narrowed to fit in Tofino 1's 5-nibble (20-bit)
     * range-match key budget:
     *   - R1: delta compared in bit<16> wrap-window (see sentinel scheme below);
     *         threshold 14400 sec < 65535, fits.
     *   - R4: session_bytes_val[31:16] is a bit<16> field giving 64 KiB
     *         granularity; 2 MB / 64 KiB = 32 units → threshold constant.
     */
    const bit<16> R1_MIN_INTERVAL_SEC = 16w14400;    /* 4 h */
    const bit<16> R4_MAX_BYTES_UNITS  = 16w32;       /* 2 MB in 64 KiB units */

    action set_r1_fired() { meta.r1_fired = 1; }
    table r1_threshold_check {
        key = { meta.r1_last_seen_sec : range; }
        actions = { set_r1_fired; @defaultonly NoAction; }
        size = 2;
        const entries = {
            (16w0 .. 16w14399) : set_r1_fired();
        }
        default_action = NoAction;
    }

    /* R4 range-match on the upper 16 bits of session_bytes_val (populated by
     * the compute_r4_bytes_check action below). Units are 64 KiB. Threshold
     * 2 MB = 32 units, so range (33..0xFFFF) fires. */
    action set_r4_fired() { meta.r4_fired = 1; }
    table r4_threshold_check {
        key = { meta.r4_bytes_check : range; }
        actions = { set_r4_fired; @defaultonly NoAction; }
        size = 2;
        const entries = {
            (16w33 .. 16w0xFFFF) : set_r4_fired();
        }
        default_action = NoAction;
    }

    /* Derive the narrow R4 compare key from session_bytes_val. Bit slice is
     * a PHV-rewire, no arithmetic — safe in a single stage. */
    action compute_r4_bytes_check() {
        meta.r4_bytes_check = meta.session_bytes_val[31:16];
    }

    /* Derive bit<16> low half of coarse_time_sec for R1 SALU input. */
    action narrow_coarse_time() {
        meta.coarse_time_sec_lo = meta.coarse_time_sec[15:0];
    }

    /* ---------- coarse_time_sec (controller writes every 1 s) ---------- */
    Register<bit<32>, bit<1>>(1, 0) coarse_time_reg;

    RegisterAction<bit<32>, bit<1>, bit<32>>(coarse_time_reg) coarse_time_read = {
        void apply(inout bit<32> v, out bit<32> r) { r = v; }
    };

    /* ---------- R1 per-BMS last-seen (returns delta) ----------
     *
     * Register narrowed to bit<16> so the downstream range-match threshold
     * key fits in the 5-nibble Tofino 1 budget. coarse_time_sec_lo is the
     * low 16 bits of seconds-since-epoch, wrapping every ~18.2 h (well over
     * the 4 h R1 threshold).
     *
     * Sentinel scheme: on write we store `coarse_time_sec_lo | 1`, so the
     * slot is guaranteed non-zero after any real update. `v == 0` in the
     * SALU therefore unambiguously means "never seen before" → return
     * 0xFFFF so the range-match threshold check (0..14399) misses and R1
     * does NOT fire on the first-ever packet. The `| 1` introduces at most
     * a 1-second quantisation error in the delta, well below R1's 4-hour
     * granularity.
     */
    Register<bit<16>, bit<8>>(256, 0) r1_last_seen_reg;

    /* C1 (review) NOTE: the `if (v == 0)` sentinel below was intended to
     * return 0xFFFF on never-seen slots so first-packet R1 cannot fire on
     * a fresh deployment. It compiles, but on our SDE 9.13.2 build the
     * sentinel branch did not appear to execute under live traffic. The
     * authoritative fix is the controller-side `init_r1_register()` re-seed
     * (controller/ota_shield_controller.py), which writes
     * `(coarse_lo + 32768) mod 65536` to every used slot at startup AND
     * after every SIGUSR1 reset. The seeded margin (≈ 32768 s ≈ 9 h
     * worst case at boot, ≈ 5 h after coarse_lo drift) bounds first-
     * packet false positives.
     *
     * We keep the SALU sentinel branch as belt-and-suspenders defence —
     * if a future SDE compiles it correctly, behaviour only improves.
     * Reviewers asking why both are present: the seeding is correctness;
     * the sentinel is forward-compatibility.
     *
     * T1.6.b — gate R1 register update on r2_fired==0 (secondary
     * poisoning vector closure). The smoke for T1.6 (R6 poisoning)
     * surfaced a sister defect: an unauthorised OTA-shaped packet still
     * triggered R2 (drop) but ALSO updated r1_last_seen_reg, polluting
     * the per-BMS replay-window state. A legitimate follow-up update
     * from an authorised source within R1_MIN_INTERVAL_SEC then false-
     * fired R1, allowing an unauthorised attacker to deny legitimate
     * firmware updates by emitting a single dropped probe.
     *
     * Same RoCE-inspired probe-then-commit pattern as T1.6 R6:
     *   1. r1_delta_probe (read-only): emits the delta used by
     *      r1_threshold_check; never mutates the register.
     *   2. r1_delta_commit (gated write): advances v only when
     *      meta.r2_fired == 0, so unauthorised packets cannot pollute
     *      replay-detection state.
     * Two RegisterActions on the same register array co-stage on
     * Tofino 1 (validated via T1.6 R6 + Spike 5 / 3a-paired). Stage
     * delta vs old single-action SALU is +1 (probe + commit).
     * meta.r2_fired is resolved upstream by r2_authorized_sources
     * (ingress_control.p4) before SecondaryRules runs. */
    /* T1.6.b/D1 v1.2 — drop the `(v == 0)` sentinel branch. Direct
     * register dump after the v1.1 deploy showed R1 false-firing on
     * every authorized OTA packet to a fresh slot. Bytecode inspection
     * revealed bf-p4c on SDE 9.13.2 emits `equ lo, lo` (always TRUE)
     * for the `(v == 0)` test on a bit<16> SALU input, then routes the
     * output to `alu_hi` which is the unused upper-16-bit half of a
     * bit<16> register (always 0). Result: meta.r1_last_seen_sec = 0,
     * which is inside r1_threshold_check's [0..14399] range, so R1
     * fires regardless of stored v.
     *
     * The original P4 source (pre-D1) kept the sentinel as
     * "belt-and-suspenders" but already noted the sentinel branch
     * "did not appear to execute under live traffic" on this SDE; my
     * D1 split made the miscompile observable on every packet. The
     * authoritative first-packet handling is the controller-side seed
     * `(coarse + 32768) % 65536`, which keeps the delta out of the
     * fire range for the first ~9 hours after a SIGUSR1 reset. We
     * remove the sentinel from both probe and commit so the SALU
     * compiles to a single subtract. */
    RegisterAction<bit<16>, bit<8>, bit<16>>(r1_last_seen_reg)
    r1_delta_probe = {
        void apply(inout bit<16> v, out bit<16> r) {
            r = meta.coarse_time_sec_lo - v;
        }
    };
    /* Commit emits the SAME delta as probe (read old v, then update v),
     * for the same single-SALU collapse reason as before. Now sentinel-
     * free so the bf-p4c miscompile is gone. */
    RegisterAction<bit<16>, bit<8>, bit<16>>(r1_last_seen_reg)
    r1_delta_commit = {
        void apply(inout bit<16> v, out bit<16> r) {
            r = meta.coarse_time_sec_lo - v;
            v = meta.coarse_time_sec_lo | 16w1;
        }
    };

    apply {
        /* Always read coarse_time so the phase-5 digest reports it. */
        meta.coarse_time_sec     = coarse_time_read.execute(0);
        narrow_coarse_time();
        meta.r1_min_interval_val = R1_MIN_INTERVAL_SEC;     /* digest */
        meta.r4_threshold_val    = R4_MAX_BYTES_UNITS;      /* digest (in 64 KiB units) */
        compute_r4_bytes_check();

        /* R1 side-effect (register update) is internally guarded.
         * The fire-check compare lives OUTSIDE the guard to break the
         * predicate chain — bf-p4c otherwise combines guards with the
         * 32-bit delta compare and exceeds the 44-bit MAU predicate limit.
         *
         * r1_last_seen_sec is parser-initialised to 0xFFFFFFFF, so non-OTA
         * packets fail the compare (MAX < 14400 is false) and don't
         * spuriously fire R1. For OTA packets, the register action
         * overwrites this field with the computed delta.
         */
        if (meta.is_ota == 1 &&
            meta.is_mqtt_publish == 1 &&
            meta.has_ota_hdr == 1 &&
            meta.bms_known == 1)
        {
            meta.r1_last_seen_sec = r1_delta_probe.execute(meta.bms_idx);
            if (meta.r2_fired == 0) {
                r1_delta_commit.execute(meta.bms_idx);
            }
        }
        /* Range-match threshold checks — bypass gateway PHV input limit.
         * r1_last_seen_sec parser-inits to 0xFFFFFFFF so non-OTA packets
         * miss the 0..14399 range. session_bytes_val parser-inits to 0,
         * so non-OTA packets miss the 2097153..MAX range. */
        r1_threshold_check.apply();
        r4_threshold_check.apply();
    }
}

#endif /* _OTA_SHIELD_SECONDARY_RULES_P4_ */

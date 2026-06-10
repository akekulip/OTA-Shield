/* OTA-Shield — ingress_control.p4
 *
 * L2 forward + classify digest.
 * MQTT PUBLISH digest.
 * OTA topic classifier + session manager + finalize digest.
 * R5 fleet monitor (Bloom-gated distinct-target counter).
 * R1/R2/R4 secondary rules (+ combined rule-alert digest).
 */

#ifndef _OTA_SHIELD_INGRESS_CONTROL_P4_
#define _OTA_SHIELD_INGRESS_CONTROL_P4_

#include "headers.p4"
#include "session_manager.p4"
#include "fleet_monitor.p4"
#include "secondary_rules.p4"
#include "policy_engine.p4"
#include "rule_r6_rollback.p4"

const port_t PORT_VISION = 8;
const port_t PORT_HULK   = 9;   /* 15/1 = DEV_PORT 9 (links at 25G); 15/3 = 11 was stale */
const port_t PORT_CPU    = 64;

control Ingress(
    inout header_t                                  hdr,
    inout metadata_t                                meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    SessionManager()  sessions;
    FleetMonitor()    fleet;
    SecondaryRules()  rules;
    PolicyEngine()    policy;
    RuleR6Rollback()  r6;

    /* ---------- Actions ---------- */
    action forward(port_t egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
    }
    action drop() { ig_dprsr_md.drop_ctl = 1; }

    action send_phase1_digest() { ig_dprsr_md.digest_type = 1; }
    action send_phase2_digest() { ig_dprsr_md.digest_type = 2; }
    action send_phase3_digest() { ig_dprsr_md.digest_type = 3; }
    action send_phase4_digest() { ig_dprsr_md.digest_type = 4; }
    action send_phase5_digest() { ig_dprsr_md.digest_type = 5; }
    action send_phase6_digest() { ig_dprsr_md.digest_type = 6; }

    action set_ota_flag() { meta.is_ota = 1; }

    /* Session-action override table — controller installs short-
     * lived entries to force DROP (or PASS) on traffic that failed policy
     * evaluation. T1.7 (Panel-7): promoted from src-IP-only to a 5-tuple
     * key (src_addr, dst_addr, dst_port, protocol, src_port) at size 256.
     * Source-IP-only keying conflated unrelated 5-tuples from the same
     * source and capped at 64 entries (saturated at ~62 in E13). The
     * 5-tuple at size 256 admits 200 distinct sources × ~1.2 concurrent
     * flows without RESOURCE_EXHAUSTED rejects, and an ALLOW for one
     * 5-tuple no longer authorizes unrelated traffic from the same src. */
    action session_deny() { meta.action_code = 2; /* DROP */ }
    action session_allow() { meta.action_code = 0; /* PASS override */ }
    table session_action_override {
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.ipv4.dst_addr : exact;
            hdr.tcp.dst_port  : exact;
            hdr.ipv4.protocol : exact;
            hdr.tcp.src_port  : exact;
        }
        actions = { session_deny; session_allow; @defaultonly NoAction; }
        size = 256;
        default_action = NoAction;
    }

    /* T1.5 (Panel-7) — HOLD-leak DP self-install marker.
     *
     * Optimistic-forward + DP self-install (Option A from
     * agent-reports/panel-7-2026-04-29/02_p4_correctness_fix.md §1).
     * On a HOLD verdict the trigger packet is forwarded; subsequent
     * packets from the same source are dropped at the deparser within
     * one MAU pass (before the controller's override entry lands).
     * Bytes-leaked per HOLD event drops from ~9.4 KB (controller install
     * p95) to one MQTT PUBLISH (~1.4 KB). */
    /* Tofino-1 constraint discovered at first compile attempt: a register
     * array can only be accessed in ONE MAU stage. The original two-SALU
     * (probe at stage N, arm at stage M>N) layout was rejected by bf-p4c
     * with "Table placement was not able to allocate ... in the same stage
     * along with Register Ingress.hold_armed_reg". The DDoS-side Spike 6
     * (`/home/philip/plan/paper-roce-ddos/p4-spikes/dp_hard_block_spike.p4`)
     * proved the working pattern: combine probe+arm into ONE SALU that
     * always reads and conditionally arms based on metadata. The (K+1)-th
     * packet from the same source observes the persisted cell and is
     * dropped at deparser. Same-packet K-th arm is fine — it triggers its
     * own drop, identical to the Spike-6 result on the DDoS detector. */
    Register<bit<8>, bit<8>>(256, 0) hold_armed_reg;
    RegisterAction<bit<8>, bit<8>, bit<8>>(hold_armed_reg) hold_armed_combo = {
        void apply(inout bit<8> v, out bit<8> r) {
            if (meta.arm_eligible == 1) {  /* RV-4: only R5-driven HOLDs arm (set in policy_engine set_hold_arm) */
                v = 8w1;                   /* arm the slot */
            }
            r = v;                         /* always read */
        }
    };

    /* CRC16(hdr.ipv4.src_addr) -> bit<8> low byte. Distinct from
     * fleet_monitor.p4's h{0,1,2} (which key on dst_addr) and from
     * session_manager.p4's session_hash (CRC32 5-tuple). */
    Hash<bit<8>>(HashAlgorithm_t.CRC16) hash_src_ip_for_hold;
    action set_src_idx() {
        meta.src_idx = hash_src_ip_for_hold.get({ hdr.ipv4.src_addr });
    }

    /* Derive varint_len from extracted header validity — parser-side
     * re-assignment isn't permitted on Tofino. Cheap byte-flag compares. */
    action set_varint_len_1() { meta.varint_len = 1; }
    action set_varint_len_2() { meta.varint_len = 2; }
    action set_varint_len_3() { meta.varint_len = 3; }
    action set_varint_len_4() { meta.varint_len = 4; }

    /* ---------- R2: authorized-source exact match ---------- */
    action mark_r2_fired() { meta.r2_fired = 1; }

    table r2_authorized_sources {
        key = { hdr.ipv4.src_addr : exact; }
        actions = { NoAction; @defaultonly mark_r2_fired; }
        size = 16;
        default_action = mark_r2_fired;
    }

    /* ---------- Per-BMS index table (AF-004 collision-free keying) ---------- */
    action set_bms_idx(bit<8> idx) {
        meta.bms_idx   = idx;
        meta.bms_known = 1;
    }

    table bms_ip_to_idx {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = { set_bms_idx; @defaultonly NoAction; }
        size = 128;     /* 64 BMS + spare slots for future expansion */
        default_action = NoAction;
    }

    /* ---------- L2 forwarding ---------- */
    table l2_forward {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { forward; drop; @defaultonly NoAction; }
        size = 4;
        default_action = NoAction;
        const entries = {
            (PORT_VISION): forward(PORT_HULK);
            (PORT_HULK):   forward(PORT_VISION);
        }
    }

    /* ---------- OTA topic prefix classifier ---------- */
    table ota_topic_prefix_match {
        key = { hdr.mqtt_topic.bytes : ternary; }
        actions = { set_ota_flag; @defaultonly NoAction; }
        size = 8;
        default_action = NoAction;
    }

    apply {
        /* 1. Forwarding */
        l2_forward.apply();

        /* 2. Derived metadata.
         *    Tofino 1 stateful ALU can only subtract a *constant* in one
         *    stage. Runtime-computed operands (ihl<<2, data_offset<<2)
         *    require a multi-stage action, which bf-p4c rejects.
         *
         *    Our simulation packets always use standard IPv4 (ihl=5, 20 B)
         *    and TCP (data_offset=5, 20 B) headers with no options — total
         *    L3+L4 header = 40 bytes. Subtract the constant; single stage.
         *    Documented limit: if a real deployment uses IP/TCP options,
         *    l4_payload_len under-reports by up to 20 extra bytes.
         */
        meta.ts_lo32        = ig_prsr_md.global_tstamp[31:0];
        meta.l4_payload_len = hdr.ipv4.total_len - 16w40;

        /* 3. TCP FIN|RST detection. */
        if (hdr.tcp.isValid() && (hdr.tcp.flags & TCP_FLAG_END) != 0) {
            meta.is_session_end = 1;
        }

        /* 4. BMS index lookup (for R1). */
        if (hdr.ipv4.isValid()) {
            bms_ip_to_idx.apply();
        }

        /* 5. OTA topic classifier + magic check. */
        if (meta.is_mqtt_publish == 1) {
            ota_topic_prefix_match.apply();
            if (hdr.ota.isValid() && hdr.ota.magic == OTA_MAGIC) {
                meta.has_ota_hdr = 1;
            }
        }

        /* 6. R2 authorised-source check (fires on any OTA traffic from
         * unlisted source; cheap MAT, default action fires R2). */
        if (meta.is_ota == 1 && hdr.ipv4.isValid()) {
            r2_authorized_sources.apply();
        }

        /* 7. Session state (MQTT or Modbus TCP). */
        if (hdr.tcp.isValid() && (meta.is_mqtt == 1 || meta.is_modbus == 1)) {
            sessions.apply(hdr, meta);
        }

        /* 8. R5 fleet monitor — called unconditionally. The internal control
         *    guards Bloom+count_update for OTA packets only; the final
         *    threshold compare is unconditional (r5_count_val stays 0 for
         *    non-OTA packets, so compare is safe). This layout breaks the
         *    predicate chain that otherwise exceeds the MAU 44-bit limit. */
        fleet.apply(hdr, meta);

        /* 9. R1 / R4 secondary rules — same unconditional-apply pattern.
         *    r1_last_seen_sec parser-init is 0xFFFFFFFF to keep R1 compare safe. */
        rules.apply(hdr, meta);
        r6.apply(hdr, meta);

        /* 9a. Derive varint_len from extracted header validity. Only run if
         * the MQTT fixed header was actually parsed. */
        if (hdr.mqtt_fh.isValid()) {
            if (hdr.mqtt_rl3.isValid()) {
                set_varint_len_4();
            } else if (hdr.mqtt_rl2.isValid()) {
                set_varint_len_3();
            } else if (hdr.mqtt_rl1.isValid()) {
                set_varint_len_2();
            } else {
                set_varint_len_1();
            }
        }

        /* 9b. Combine rule fires into an action_code (PASS/HOLD/
         * DROP). Unconditional apply to keep predicate chain short; inside,
         * each clause is a single byte-flag compare. */
        policy.apply(hdr, meta);

        /* 9c. Controller-installed session-action override (HOLD
         * policy enforcement). Runs only on TCP flows; keys on 5-tuple
         * (src_addr, dst_addr, dst_port, protocol, src_port).
         *
         * T1.5 — HOLD-leak DP self-install marker. Before consulting the
         * override table, probe hold_armed_reg[CRC16(src_ip)]; if armed
         * (a previous packet from this source got a HOLD verdict), force
         * DROP without waiting for the controller's override entry. After
         * the override apply, if the verdict is HOLD (action_code == 1)
         * the trigger packet still forwards (optimistic) but the marker
         * is set so subsequent packets are caught above. */
        if (hdr.tcp.isValid() && hdr.ipv4.isValid()) {
            set_src_idx();
            session_action_override.apply();
            /* hold_armed_combo is ONE SALU on hold_armed_reg per Tofino-1
             * single-stage register-access rule. It reads the current
             * armed state AND, if action_code==1 (controller HOLD verdict),
             * arms the slot — both in the same SALU action. */
            bit<8> armed_state = hold_armed_combo.execute(meta.src_idx);
            if (armed_state == 1 && meta.action_code != 2) {
                meta.action_code = 2;  /* drop subsequent packets from same src */
            }
        }

        /* 9d. If action_code resolves to DROP, drop the packet at the
         * deparser. HOLD trigger packets still forward (controller will
         * decide); phase6 digest lets the controller see the decision
         * and install a session override. T1.5: subsequent packets from
         * the same source are caught by hold_armed_probe above. */
        if (meta.action_code == 2) {
            drop();
        }

        /* 10. Digest priority (one per packet):
         *     HOLD/DROP decisions beat rule alerts which
         *     beat session-finalise which beats MQTT-parse which beats
         *     classify. Policy digest carries the highest signal: it tells
         *     the controller both what rules fired AND what action was
         *     chosen, so the controller can react with one subscription.
         */
        if (meta.action_code != 0) {
            send_phase6_digest();
        } else if (meta.r5_fired == 1) {
            send_phase4_digest();
        } else if (meta.r1_fired == 1 ||
                   meta.r2_fired == 1 ||
                   meta.r4_fired == 1) {
            send_phase5_digest();
        } else if (meta.is_session_end == 1 &&
                   hdr.tcp.isValid() &&
                   (meta.is_mqtt == 1 || meta.is_modbus == 1)) {
            send_phase3_digest();
        } else if (meta.is_mqtt_publish == 1) {
            send_phase2_digest();
        } else if (hdr.tcp.isValid() && (meta.is_mqtt == 1 || meta.is_modbus == 1)) {
            send_phase1_digest();
        }
    }
}

control Egress(
    inout header_t                                    hdr,
    inout metadata_t                                  meta,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t    eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t   eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    apply {
        /* Egress is passthrough. */
    }
}

#endif /* _OTA_SHIELD_INGRESS_CONTROL_P4_ */

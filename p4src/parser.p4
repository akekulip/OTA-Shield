/* OTA-Shield — parser.p4
 *
 * Phase 1: Ethernet → IPv4 → TCP. Identify MQTT (1883) and Modbus (502).
 * Phase 2: MQTT fixed header (with 1–4 byte VarInt), topic length, 32-byte
 *          topic slot, packet identifier (QoS=1), 20-byte OTA header.
 * Phase 6: Modbus MBAP extraction.
 *
 * Parser state budget: 32 (Gate 2 target). Current states: ~14. Under budget.
 *
 * Simulation conventions (Definition 5.1, 5.11):
 *   - QoS=1 always → packet identifier is always present.
 *   - Topics null-padded to 32 bytes → fixed-size extraction is correct.
 */

#ifndef _OTA_SHIELD_PARSER_P4_
#define _OTA_SHIELD_PARSER_P4_

#include "headers.p4"

parser IngressParser(
    packet_in                       pkt,
    out header_t                    hdr,
    out metadata_t                  meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.is_mqtt            = 0;
        meta.is_modbus          = 0;
        meta.is_mqtt_publish    = 0;
        meta.has_ota_hdr        = 0;
        meta.is_ota             = 0;
        meta.is_session_end     = 0;   /* AF-001: explicit zero-init */
        meta.varint_len         = 0;
        meta.action_code        = 0;
        meta.arm_eligible       = 0;   /* RV-4 fix: default not cascade-eligible */
        meta.ota_version_parsed = 0;
        meta.ota_size_parsed    = 0;
        meta.l4_payload_len     = 0;
        meta.session_id         = 0;
        meta.session_bytes_val  = 0;
        meta.session_first_ts_val = 0;
        meta.ts_lo32            = 0;
        meta.r5_bf_hit0         = 0;
        meta.r5_bf_hit1         = 0;
        meta.r5_bf_hit2         = 0;
        meta.r5_all_hit         = 0;
        meta.r5_count_val       = 0;
        meta.r5_threshold_val   = 0;
        meta.r5_fired           = 0;
        meta.r1_fired           = 0;
        meta.r2_fired           = 0;
        meta.r4_fired           = 0;
        meta.r6_fired           = 0;
        meta.coarse_time_sec    = 0;
        meta.bms_idx            = 0;
        meta.bms_known          = 0;
        meta.r1_last_seen_sec   = 16w0xFFFF;  /* non-OTA packets default to "infinity" so R1 compare is safe */
        meta.r1_min_interval_val = 0;
        meta.r4_threshold_val   = 0;
        meta.r4_bytes_check     = 0;
        meta.coarse_time_sec_lo = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etype) {
            ETHERTYPE_IPV4: parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            default:      accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.dst_port) {
            TCP_PORT_MQTT:   mark_mqtt;
            TCP_PORT_MODBUS: mark_modbus;
            default:         accept;
        }
    }

    state mark_mqtt {
        meta.is_mqtt = 1;
        transition parse_mqtt_fh;
    }

    state mark_modbus {
        meta.is_modbus = 1;
        transition parse_modbus;
    }

    /* ---------- MQTT path ----------
     *
     * parse_mqtt_fh extracts the fixed header byte 1 and the first VarInt byte.
     * The VarInt continues via parse_rl1/2/3 if the MSB of the previous byte is set.
     * We only parse the PUBLISH variable header when mtype == PUBLISH (3).
     * For non-PUBLISH MQTT packets we accept after the fixed header — the
     * controller does not need further detail.
     */

    /* varint_len is derived in ingress from header validity — Tofino
     * rejects re-assignment of the same metadata field across parser states
     * ("clear-on-write semantic"). We extract each length-byte and let the
     * ingress apply block derive `meta.varint_len` from isValid(). */
    state parse_mqtt_fh {
        pkt.extract(hdr.mqtt_fh);
        transition select(hdr.mqtt_fh.rl0[7:7]) {
            1w0: after_varint;
            1w1: parse_rl1;
        }
    }

    state parse_rl1 {
        pkt.extract(hdr.mqtt_rl1);
        transition select(hdr.mqtt_rl1.b[7:7]) {
            1w0: after_varint;
            1w1: parse_rl2;
        }
    }

    state parse_rl2 {
        pkt.extract(hdr.mqtt_rl2);
        transition select(hdr.mqtt_rl2.b[7:7]) {
            1w0: after_varint;
            1w1: parse_rl3;
        }
    }

    state parse_rl3 {
        pkt.extract(hdr.mqtt_rl3);
        transition after_varint;
    }

    state after_varint {
        /* Only parse variable header + payload prefix for PUBLISH. */
        transition select(hdr.mqtt_fh.mtype) {
            MQTT_TYPE_PUBLISH: parse_mqtt_topic_len;
            default:           accept;
        }
    }

    state parse_mqtt_topic_len {
        pkt.extract(hdr.mqtt_tlen);
        transition parse_mqtt_topic;
    }

    state parse_mqtt_topic {
        /* 32-byte null-padded topic slot (simulation convention). */
        pkt.extract(hdr.mqtt_topic);
        meta.is_mqtt_publish = 1;
        /* QoS=0 has no packet identifier, so OTA header
         * starts 2 B earlier. QoS lives in flags[2:1] of the fixed-header
         * flags nibble. QoS=1 and QoS=2 both carry the pkt-id. */
        transition select(hdr.mqtt_fh.flags[2:1]) {
            2w0:     parse_ota_hdr;
            default: parse_mqtt_pid;
        }
    }

    state parse_mqtt_pid {
        /* Packet identifier (QoS=1 always in simulation). */
        pkt.extract(hdr.mqtt_pid);
        transition parse_ota_hdr;
    }

    state parse_ota_hdr {
        /* First 20 bytes of the PUBLISH payload = OTA header. */
        pkt.extract(hdr.ota);
        meta.ota_version_parsed = hdr.ota.version;
        meta.ota_size_parsed    = hdr.ota.size;
        /* has_ota_hdr is a metadata signal; final determination (magic match)
         * happens in ingress control to keep parser branchless and bounded. */
        transition accept;
    }

    /* ---------- Modbus path ---------- */
    state parse_modbus {
        pkt.extract(hdr.modbus);
        transition accept;
    }
}

/* Egress parser — same as ingress up to TCP. Egress has no OTA-specific logic
 * in any phase, so we do not re-parse the MQTT variable header here. */
parser EgressParser(
    packet_in                       pkt,
    out header_t                    hdr,
    out metadata_t                  meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        /* Zero-init the `out metadata_t meta` param so bf-p4c is happy;
         * egress doesn't use any of these fields, they just need defined
         * initial values. */
        meta.is_mqtt            = 0;
        meta.is_modbus          = 0;
        meta.is_mqtt_publish    = 0;
        meta.has_ota_hdr        = 0;
        meta.is_ota             = 0;
        meta.is_session_end     = 0;
        meta.varint_len         = 0;
        meta.action_code        = 0;
        meta.arm_eligible       = 0;   /* RV-4 fix: default not cascade-eligible */
        meta.ota_version_parsed = 0;
        meta.ota_size_parsed    = 0;
        meta.l4_payload_len     = 0;
        meta.session_id         = 0;
        meta.session_bytes_val  = 0;
        meta.session_first_ts_val = 0;
        meta.ts_lo32            = 0;
        meta.r5_bf_hit0         = 0;
        meta.r5_bf_hit1         = 0;
        meta.r5_bf_hit2         = 0;
        meta.r5_all_hit         = 0;
        meta.r5_count_val       = 0;
        meta.r5_threshold_val   = 0;
        meta.r5_fired           = 0;
        meta.r1_fired           = 0;
        meta.r2_fired           = 0;
        meta.r4_fired           = 0;
        meta.r6_fired           = 0;
        meta.coarse_time_sec    = 0;
        meta.bms_idx            = 0;
        meta.bms_known          = 0;
        meta.r1_last_seen_sec   = 16w0xFFFF;  /* non-OTA packets default to "infinity" so R1 compare is safe */
        meta.r1_min_interval_val = 0;
        meta.r4_threshold_val   = 0;
        meta.r4_bytes_check     = 0;
        meta.coarse_time_sec_lo = 0;
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etype) {
            ETHERTYPE_IPV4: parse_ipv4;
            default:        accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            default:      accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

#endif /* _OTA_SHIELD_PARSER_P4_ */

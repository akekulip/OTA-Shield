/* OTA-Shield — deparser.p4
 *
 * Standard deparse + digest emission.
 *   digest_type 1 → phase1_classify_digest_t
 *   digest_type 2 → phase2_mqtt_digest_t
 *   digest_type 3 → phase3_session_digest_t (TCP FIN/RST on tracked flow)
 *   digest_type 4 → phase4_r5_alert_digest_t (R5 threshold crossed)
 */

#ifndef _OTA_SHIELD_DEPARSER_P4_
#define _OTA_SHIELD_DEPARSER_P4_

#include "headers.p4"

control IngressDeparser(
    packet_out                                      pkt,
    inout header_t                                  hdr,
    in    metadata_t                                meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Digest<phase1_classify_digest_t>()   classify_digest;
    Digest<phase2_mqtt_digest_t>()       mqtt_digest;
    Digest<phase3_session_digest_t>()    session_digest;
    Digest<phase4_r5_alert_digest_t>()   r5_digest;
    Digest<phase5_rule_alert_digest_t>() rule_digest;
    Digest<phase6_hold_digest_t>()       hold_digest;

    apply {
        if (ig_dprsr_md.digest_type == 1) {
            classify_digest.pack({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                meta.is_mqtt,
                meta.is_modbus,
                meta.session_id   /* M5 */
            });
        }
        if (ig_dprsr_md.digest_type == 2) {
            /* Pack only the first 12 bytes (upper 96 bits) of the 32-byte
             * topic slot — keeps the digest under Tofino 1's 48-byte learn
             * quantum. Sufficient to cover "/ota/bms/NN" (11 bytes). */
            mqtt_digest.pack({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                hdr.mqtt_topic.bytes[255:160],
                hdr.ota.magic,
                hdr.ota.version,
                hdr.ota.size,
                meta.varint_len,
                meta.has_ota_hdr,
                meta.is_ota
            });
        }
        if (ig_dprsr_md.digest_type == 3) {
            session_digest.pack({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                meta.session_id,
                meta.session_bytes_val,
                meta.session_first_ts_val,
                meta.ts_lo32,
                meta.is_ota,
                meta.has_ota_hdr,
                hdr.ota.version,
                hdr.ota.size,
                hdr.tcp.flags
            });
        }
        if (ig_dprsr_md.digest_type == 4) {
            r5_digest.pack({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                meta.r5_count_val,
                meta.r5_threshold_val,
                hdr.ota.version,
                hdr.ota.size
            });
        }
        if (ig_dprsr_md.digest_type == 6) {
            hold_digest.pack({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                meta.session_id,
                meta.bms_idx,
                meta.action_code,
                meta.r1_fired,
                meta.r2_fired,
                meta.r4_fired,
                meta.r5_fired,
                hdr.ota.version,
                hdr.ota.size,
                meta.r6_fired
            });
        }
        if (ig_dprsr_md.digest_type == 5) {
            rule_digest.pack({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.tcp.src_port,
                hdr.tcp.dst_port,
                meta.session_id,
                meta.bms_idx,
                meta.session_bytes_val,
                hdr.ota.version,
                hdr.ota.size,
                meta.coarse_time_sec,
                meta.r1_last_seen_sec,
                meta.r4_threshold_val,
                meta.r1_fired,
                meta.r2_fired,
                meta.r4_fired,
                meta.is_session_end,
                hdr.tcp.flags
            });
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.mqtt_fh);
        pkt.emit(hdr.mqtt_rl1);
        pkt.emit(hdr.mqtt_rl2);
        pkt.emit(hdr.mqtt_rl3);
        pkt.emit(hdr.mqtt_tlen);
        pkt.emit(hdr.mqtt_topic);
        pkt.emit(hdr.mqtt_pid);
        pkt.emit(hdr.ota);
        pkt.emit(hdr.modbus);
    }
}

control EgressDeparser(
    packet_out                                      pkt,
    inout header_t                                  hdr,
    in    metadata_t                                meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}

#endif /* _OTA_SHIELD_DEPARSER_P4_ */

/* OTA-Shield — headers.p4
 *
 * Header definitions for the Tofino Native Architecture pipeline.
 *   Ethernet, IPv4, TCP.
 *   MQTT fixed header (VarInt 1–4 bytes), topic prefix, packet ID,
 *     20-byte OTA header (Definition 5.1).
 *   Session manager metadata + session-finalize digest.
 *
 * Simulation conventions (see definitions/05_attack_specs.md §5.1, §5.11):
 *   - MQTT PUBLISH frames use QoS=1 → packet identifier always present.
 *   - Topics null-padded to exactly 32 bytes.
 */

#ifndef _OTA_SHIELD_HEADERS_P4_
#define _OTA_SHIELD_HEADERS_P4_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
typedef bit<9>  port_t;

const ether_type_t ETHERTYPE_IPV4 = 0x0800;
const ether_type_t ETHERTYPE_ARP  = 0x0806;

const bit<8> IP_PROTO_TCP  = 6;
const bit<8> IP_PROTO_UDP  = 17;
const bit<8> IP_PROTO_ICMP = 1;

const bit<16> TCP_PORT_MQTT   = 1883;
const bit<16> TCP_PORT_MODBUS = 502;

/* TCP flag bits (wire order: bit 0 = FIN, bit 7 = CWR). */
const bit<8> TCP_FLAG_FIN = 0x01;
const bit<8> TCP_FLAG_SYN = 0x02;
const bit<8> TCP_FLAG_RST = 0x04;
const bit<8> TCP_FLAG_END = 0x05;   /* FIN | RST — session-ending */

const bit<4> MQTT_TYPE_CONNECT   = 1;
const bit<4> MQTT_TYPE_CONNACK   = 2;
const bit<4> MQTT_TYPE_PUBLISH   = 3;
const bit<4> MQTT_TYPE_SUBSCRIBE = 8;

const bit<32> OTA_MAGIC = 0x4F544153;   /* "OTAS" */

/* Session table sizing.
 * 2^16 entries is sufficient for the 50-BMS testbed with heavy concurrency.
 * Each u32 register occupies 256 KB, comfortably in one MAU stage on Tofino 1.
 */
const bit<32> SESSION_TABLE_SIZE    = 65536;
typedef bit<16> session_idx_t;

/* ---------- L2 ---------- */
header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t etype;
}

/* ---------- L3 ---------- */
header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

/* ---------- L4 ---------- */
header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

/* ---------- MQTT ---------- */
header mqtt_fh_h {
    bit<4> mtype;
    bit<4> flags;
    bit<8> rl0;
}
header mqtt_rl_b_h      { bit<8>  b; }
header mqtt_topic_len_h { bit<16> len; }
header mqtt_topic32_h   { bit<256> bytes; }
header mqtt_pkt_id_h    { bit<16>  pkt_id; }

/* ---------- OTA header ---------- */
header ota_hdr_h {
    bit<32> magic;
    bit<32> version;
    bit<32> size;
    bit<64> hash_hint;
}

/* ---------- Modbus MBAP (stub) ---------- */
header modbus_mbap_h {
    bit<16> txn_id;
    bit<16> proto_id;
    bit<16> length;
    bit<8>  unit_id;
    bit<8>  func_code;
}

/* ---------- Header bundle ---------- */
struct header_t {
    ethernet_h       ethernet;
    ipv4_h           ipv4;
    tcp_h            tcp;

    mqtt_fh_h        mqtt_fh;
    mqtt_rl_b_h      mqtt_rl1;
    mqtt_rl_b_h      mqtt_rl2;
    mqtt_rl_b_h      mqtt_rl3;
    mqtt_topic_len_h mqtt_tlen;
    mqtt_topic32_h   mqtt_topic;
    mqtt_pkt_id_h    mqtt_pid;
    ota_hdr_h        ota;

    modbus_mbap_h    modbus;
}

/* ---------- Metadata ----------
 *
 * Tofino 1 PHV allocator prefers byte-aligned fields. Sub-byte fields
 * (bit<1>, bit<2>, bit<3>, bit<4>) can force 6-bit slice allocation when
 * adjacent to 32-bit register outputs, triggering "invalid SuperCluster"
 * errors. Widen all sub-byte fields to bit<8>. PHV cost ≈ +15 bytes/packet.
 *
 * Flag fields use bit<8> but only the LSB (0/1) is meaningful.
 * Compare with `== 1` as before; the compiler widens the literal.
 */
struct metadata_t {
    bit<8>  is_mqtt;
    bit<8>  is_modbus;
    bit<8>  is_mqtt_publish;
    bit<8>  has_ota_hdr;
    bit<8>  is_ota;
    bit<8>  is_session_end;
    bit<8>  varint_len;          /* 1..4 */
    bit<8>  action_code;
    bit<8>  src_idx;             /* T1.5: CRC16(src_addr) -> 8-bit slot for hold_armed_reg */

    session_idx_t session_id;          /* 16-bit hash */
    bit<32>       session_bytes_val;
    bit<32>       session_first_ts_val;
    bit<32>       ts_lo32;
    bit<16>       l4_payload_len;

    bit<32> ota_version_parsed;
    bit<32> ota_size_parsed;

    /* R5
     * r5_count_val narrowed to bit<16> so range-match threshold table fits in
     * Tofino 1's 5-nibble (20-bit) range-match key budget. Distinct-BMS count
     * in a 60s window is at most ~100, well under 65535. */
    bit<8>  r5_bf_hit0;
    bit<8>  r5_bf_hit1;
    bit<8>  r5_bf_hit2;
    bit<8>  r5_all_hit;
    bit<16> r5_count_val;
    bit<16> r5_threshold_val;
    bit<8>  r5_fired;

    /* R1 / R2 / R4 register state.
     * r1_last_seen_sec narrowed to bit<16> with a sentinel scheme. The register
     * stores `coarse_time_sec[15:0] | 1` (always non-zero after first write) so
     * `v == 0` in the stateful ALU unambiguously means "never seen" → return
     * 0xFFFF → range compare (0..14399) misses → no spurious fire.
     *
     * r4_bytes_check = session_bytes_val[31:16] — gives 64 KiB granularity,
     * fits in 4 nibbles for range match. R4 threshold of 2 MB ≈ 32 units. */
    bit<8>  r1_fired;
    bit<8>  r2_fired;
    bit<8>  r4_fired;
    bit<32> coarse_time_sec;
    bit<16> coarse_time_sec_lo;
    bit<8>  bms_idx;
    bit<8>  bms_known;
    bit<16> r1_last_seen_sec;
    bit<16> r1_min_interval_val;
    bit<16> r4_bytes_check;
    bit<16> r4_threshold_val;
    bit<8>  r6_fired;
    bit<8>  arm_eligible;  /* RV-4 fix: hold_armed cascade arms only on R5/R6-driven HOLDs */
}

/* ---------- Digest types ----------
 *
 * digest_type 1: Phase-1 classify digest (any MQTT/Modbus packet)
 * digest_type 2: Phase-2 MQTT parse digest (PUBLISH parsed)
 * digest_type 3: Phase-3 session-finalize digest (TCP FIN/RST on tracked flow)
 */

struct phase1_classify_digest_t {
    bit<32>       src_ip;
    bit<32>       dst_ip;
    bit<16>       src_port;
    bit<16>       dst_port;
    bit<8>        is_mqtt;
    bit<8>        is_modbus;
    session_idx_t session_id;  /* M5: CRC32 5-tuple hash; collision measurement */
}

struct phase2_mqtt_digest_t {
    bit<32>  src_ip;
    bit<32>  dst_ip;
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<96>  topic_prefix;
    bit<32>  ota_magic;
    bit<32>  ota_version;
    bit<32>  ota_size;
    bit<8>   varint_len;
    bit<8>   has_ota_hdr;
    bit<8>   is_ota;
}

struct phase4_r5_alert_digest_t {
    bit<32>  src_ip;
    bit<32>  dst_ip;
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  r5_count;
    bit<16>  r5_threshold;
    bit<32>  ota_version;
    bit<32>  ota_size;
}

/* Per-session rule-alert digest. Flag fields are individual
 * bit<8> (0 or 1) rather than a packed nibble — keeps everything byte-
 * aligned for PHV (bit<4> vectors cause SuperCluster allocation failures). */
struct phase5_rule_alert_digest_t {
    bit<32>       src_ip;
    bit<32>       dst_ip;
    bit<16>       src_port;
    bit<16>       dst_port;
    session_idx_t session_id;
    bit<8>        bms_idx;
    bit<32>       session_bytes;
    bit<32>       ota_version;
    bit<32>       ota_size;
    bit<32>       coarse_time_sec;
    bit<16>       r1_last_seen_sec;
    bit<16>       r4_threshold;
    bit<8>        r1_fired;
    bit<8>        r2_fired;
    bit<8>        r4_fired;
    bit<8>        is_session_end;
    bit<8>        tcp_flags;
}

/* HOLD-path decision digest. Emitted when action_code != PASS so
 * the controller can install a short-lived session-action override entry
 * (DROP) or allow-list override (PASS) in the session_action_override
 * table. Compact struct to stay under the 48-byte learn quantum. */
struct phase6_hold_digest_t {
    bit<32>       src_ip;
    bit<32>       dst_ip;
    bit<16>       src_port;
    bit<16>       dst_port;
    session_idx_t session_id;
    bit<8>        bms_idx;
    bit<8>        action_code;
    bit<8>        r1_fired;
    bit<8>        r2_fired;
    bit<8>        r4_fired;
    bit<8>        r5_fired;
    bit<32>       ota_version;
    bit<32>       ota_size;
    bit<8>        r6_fired;
}

struct phase3_session_digest_t {
    bit<32>       src_ip;
    bit<32>       dst_ip;
    bit<16>       src_port;
    bit<16>       dst_port;
    session_idx_t session_id;
    bit<32>       total_bytes;
    bit<32>       first_ts;
    bit<32>       last_ts;
    bit<8>        is_ota;
    bit<8>        has_ota_hdr;
    bit<32>       ota_version;
    bit<32>       ota_size;
    bit<8>        tcp_flags;
}

#endif /* _OTA_SHIELD_HEADERS_P4_ */

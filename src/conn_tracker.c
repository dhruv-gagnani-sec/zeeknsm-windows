/*
 * conn_tracker.c - Network Connection State Tracker Implementation
 *
 * Hash table design:
 *   - FNV-1a hash over the 5-tuple
 *   - Bidirectional lookup: forward key hashed first, then reverse key
 *     in a separate bucket if the hash differs
 *   - Open chaining for collision resolution
 *   - Expiry sweep called periodically from the main loop
 */

#include "conn_tracker.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

/* ============================================================
 * Wall-clock Timestamp
 * FILETIME gives 100-ns intervals since 1601-01-01.
 * Subtract the 1601-1970 offset (116444736000000000 * 100ns)
 * then divide by 10 000 000 to get Unix seconds as a double.
 * ============================================================ */
double get_timestamp(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    ULARGE_INTEGER ui;
    ui.LowPart  = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;

    uint64_t t = ui.QuadPart - 116444736000000000ULL;
    return (double)t / 10000000.0;
}

/* ============================================================
 * FNV-1a Hash on the raw 5-tuple bytes
 * ============================================================ */
static uint32_t conn_hash(const ConnKey *key) {
    uint32_t h = 2166136261u;
    const uint8_t *p = (const uint8_t *)key;
    for (size_t i = 0; i < sizeof(ConnKey); i++) {
        h ^= (uint32_t)p[i];
        h *= 16777619u;
    }
    return h & CONN_TABLE_MASK;
}

static bool key_equal(const ConnKey *a, const ConnKey *b) {
    return a->src_ip   == b->src_ip   &&
           a->dst_ip   == b->dst_ip   &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto    == b->proto;
}

static bool key_is_reverse(const ConnKey *stored, const ConnKey *incoming) {
    return stored->src_ip   == incoming->dst_ip   &&
           stored->dst_ip   == incoming->src_ip   &&
           stored->src_port == incoming->dst_port &&
           stored->dst_port == incoming->src_port &&
           stored->proto    == incoming->proto;
}

/* ============================================================
 * Zeek-Compatible conn_state String
 *
 * Mapping for TCP (Zeek terminology):
 *   S0   – SYN, no reply
 *   S1   – SYN+ACK, connection established, no data
 *   SF   – Normal connection close (both FINs)
 *   REJ  – Connection rejected (RST before handshake)
 *   S2   – Connection established, FIN from originator
 *   S3   – Connection established, FIN from responder
 *   RSTO – Connection established, RST from originator
 *   RSTR – Connection established, RST from responder
 *   RSTOS0 – RST before handshake complete (from originator)
 *   RSTRH  – RST before handshake complete (from responder)
 *   SH   – SYN then FIN from originator (half-open)
 *   SHR  – SYN then FIN from responder
 *   OTH  – Miscellaneous / mid-stream
 * ============================================================ */
const char *conn_state_str(const ConnRecord *rec) {
    uint8_t proto = rec->key.proto;

    /* UDP and ICMP have simple labels */
    if (proto == PROTO_UDP)  return "udp";
    if (proto == PROTO_ICMP) return "icmp";

    bool orig_rst = rec->orig.rst;
    bool resp_rst = rec->resp.rst;
    bool orig_fin = rec->orig.fin;
    bool resp_fin = rec->resp.fin;

    /* RST cases */
    if (orig_rst || resp_rst) {
        if (rec->state == CONN_STATE_SYN_SENT) return "RSTOS0";
        if (rec->state == CONN_STATE_SYN_RECV) return "RSTRH";
        if (orig_rst && !resp_rst)              return "RSTO";
        return "RSTR";
    }

    switch (rec->state) {
    case CONN_STATE_NEW:
        return "S0";

    case CONN_STATE_SYN_SENT:
        return orig_fin ? "SH" : "S1";

    case CONN_STATE_SYN_RECV:
        return resp_fin ? "SHR" : "S2";

    case CONN_STATE_ESTABLISHED:
        if (orig_fin && resp_fin) return "SF";
        if (orig_fin)             return "S2";
        if (resp_fin)             return "S3";
        return "S3";

    case CONN_STATE_FIN_WAIT:
        return (orig_fin && resp_fin) ? "SF" : "S2";

    case CONN_STATE_CLOSE_WAIT:
        return "S3";

    case CONN_STATE_CLOSED:
        return "SF";

    case CONN_STATE_RESET:
        return "RSTR";

    default:
        return "OTH";
    }
}

/* ============================================================
 * Init / Destroy
 * ============================================================ */
void conn_table_init(ConnTable *ct,
                     int tcp_timeout,
                     int udp_timeout,
                     int icmp_timeout) {
    memset(ct, 0, sizeof(ConnTable));
    ct->tcp_timeout  = tcp_timeout;
    ct->udp_timeout  = udp_timeout;
    ct->icmp_timeout = icmp_timeout;
}

void conn_table_destroy(ConnTable *ct) {
    for (int i = 0; i < CONN_TABLE_SIZE; i++) {
        ConnRecord *r = ct->buckets[i];
        while (r) {
            ConnRecord *next = r->next;
            free(r);
            r = next;
        }
        ct->buckets[i] = NULL;
    }
    ct->count = 0;
}

/* ============================================================
 * Lookup (forward + reverse)
 * ============================================================ */
ConnRecord *conn_table_lookup(ConnTable *ct, const ConnKey *key) {
    /* Search forward bucket */
    uint32_t idx = conn_hash(key);
    for (ConnRecord *r = ct->buckets[idx]; r; r = r->next) {
        if (key_equal(&r->key, key) || key_is_reverse(&r->key, key))
            return r;
    }
    /* Search reverse bucket (may differ due to IP swap) */
    ConnKey rkey = {
        key->dst_ip,   key->src_ip,
        key->dst_port, key->src_port,
        key->proto
    };
    uint32_t ridx = conn_hash(&rkey);
    if (ridx != idx) {
        for (ConnRecord *r = ct->buckets[ridx]; r; r = r->next) {
            if (key_equal(&r->key, &rkey) || key_is_reverse(&r->key, key))
                return r;
        }
    }
    return NULL;
}

/* ============================================================
 * Update (or Create) a Connection
 * ============================================================ */
ConnRecord *conn_table_update(ConnTable *ct,
                              const ParsedPacket *pkt,
                              double ts) {
    /* Build the forward key from this packet */
    ConnKey key;
    key.src_ip   = pkt->ip->src_addr;
    key.dst_ip   = pkt->ip->dst_addr;
    key.src_port = pkt->src_port;
    key.dst_port = pkt->dst_port;
    key.proto    = pkt->proto;

    /* ---- Search forward bucket ---- */
    uint32_t idx   = conn_hash(&key);
    ConnRecord *found = NULL;
    bool is_reverse   = false;

    for (ConnRecord *r = ct->buckets[idx]; r; r = r->next) {
        if (key_equal(&r->key, &key)) {
            found = r; is_reverse = false; break;
        }
        if (key_is_reverse(&r->key, &key)) {
            found = r; is_reverse = true; break;
        }
    }

    /* ---- Search reverse bucket if still not found ---- */
    if (!found) {
        ConnKey rkey = {
            key.dst_ip,   key.src_ip,
            key.dst_port, key.src_port,
            key.proto
        };
        uint32_t ridx = conn_hash(&rkey);
        if (ridx != idx) {
            for (ConnRecord *r = ct->buckets[ridx]; r; r = r->next) {
                if (key_equal(&r->key, &rkey)) {
                    found = r; is_reverse = true; break;
                }
            }
        }
    }

    /* ---- Allocate new record if not found ---- */
    if (!found) {
        found = (ConnRecord *)calloc(1, sizeof(ConnRecord));
        if (!found) return NULL;

        found->key      = key;
        found->ts_start = ts;
        found->state    = CONN_STATE_NEW;

        ip_to_str(pkt->ip->src_addr, found->src_ip_str, sizeof(found->src_ip_str));
        ip_to_str(pkt->ip->dst_addr, found->dst_ip_str, sizeof(found->dst_ip_str));
        uid_generate(found->uid);

        /* Best-effort service name from port */
        const char *svc = port_to_service(pkt->dst_port, pkt->proto);
        if (!svc) svc = port_to_service(pkt->src_port, pkt->proto);
        if (svc) strncpy(found->service, svc, sizeof(found->service) - 1);

        /* Insert at bucket head */
        found->next = ct->buckets[idx];
        ct->buckets[idx] = found;
        ct->count++;
        ct->total++;
        is_reverse = false;
    }

    /* ---- Update timestamps ---- */
    found->ts_last  = ts;
    found->duration = ts - found->ts_start;

    /* ---- Count bytes (IP total_length) ---- */
    uint16_t ip_bytes = ntohs(pkt->ip->total_length);
    if (!is_reverse) {
        found->orig.bytes += ip_bytes;
        found->orig.pkts++;
    } else {
        found->resp.bytes += ip_bytes;
        found->resp.pkts++;
    }

    /* ---- TCP State Machine ---- */
    if (pkt->proto == PROTO_TCP && pkt->transport.tcp) {
        uint8_t flags = pkt->transport.tcp->flags;
        bool syn = (flags & TCP_SYN) != 0;
        bool ack = (flags & TCP_ACK) != 0;
        bool fin = (flags & TCP_FIN) != 0;
        bool rst = (flags & TCP_RST) != 0;

        if (rst) {
            if (!is_reverse) found->orig.rst = true;
            else             found->resp.rst = true;
            found->state = CONN_STATE_RESET;

        } else if (fin) {
            if (!is_reverse) found->orig.fin = true;
            else             found->resp.fin = true;
            found->state = (found->orig.fin && found->resp.fin)
                           ? CONN_STATE_CLOSED : CONN_STATE_FIN_WAIT;

        } else if (syn && !ack) {
            if (found->state == CONN_STATE_NEW)
                found->state = CONN_STATE_SYN_SENT;

        } else if (syn && ack) {
            found->state = CONN_STATE_SYN_RECV;

        } else if (ack && found->state == CONN_STATE_SYN_RECV) {
            found->state = CONN_STATE_ESTABLISHED;

        } else if (found->state == CONN_STATE_NEW ||
                   found->state == CONN_STATE_SYN_SENT) {
            /* Mid-stream pickup */
            found->state = CONN_STATE_ESTABLISHED;
        }

    } else if (pkt->proto == PROTO_UDP) {
        found->state = CONN_STATE_UDP_ACTIVE;

    } else if (pkt->proto == PROTO_ICMP) {
        found->state = CONN_STATE_ICMP_ACTIVE;
    }

    return found;
}

/* ============================================================
 * Expiry Sweep
 * ============================================================ */
int conn_table_expire(ConnTable *ct,
                      double now,
                      ConnExpireCallback cb,
                      void *userdata) {
    int expired = 0;

    for (int i = 0; i < CONN_TABLE_SIZE; i++) {
        ConnRecord **pp = &ct->buckets[i];
        while (*pp) {
            ConnRecord *r = *pp;

            int timeout;
            switch (r->key.proto) {
            case PROTO_TCP:  timeout = ct->tcp_timeout;  break;
            case PROTO_UDP:  timeout = ct->udp_timeout;  break;
            case PROTO_ICMP: timeout = ct->icmp_timeout; break;
            default:         timeout = ct->tcp_timeout;  break;
            }

            /* Closed / reset connections expire immediately */
            bool force = (r->state == CONN_STATE_CLOSED ||
                          r->state == CONN_STATE_RESET);

            if (force || (now - r->ts_last) >= (double)timeout) {
                r->duration = r->ts_last - r->ts_start;
                if (cb) cb(r, userdata);
                *pp = r->next;
                free(r);
                ct->count--;
                expired++;
            } else {
                pp = &r->next;
            }
        }
    }
    return expired;
}

void conn_table_flush(ConnTable *ct,
                      ConnExpireCallback cb,
                      void *userdata) {
    for (int i = 0; i < CONN_TABLE_SIZE; i++) {
        ConnRecord *r = ct->buckets[i];
        while (r) {
            ConnRecord *next = r->next;
            r->duration = r->ts_last - r->ts_start;
            if (cb) cb(r, userdata);
            free(r);
            r = next;
        }
        ct->buckets[i] = NULL;
    }
    ct->count = 0;
}

/*
 * event_engine.c - Real-Time Detection Event Engine Implementation
 */

#include "event_engine.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * Init
 * ============================================================ */
void event_engine_init(EventEngine *eng, const ZeekConfig *cfg) {
    memset(eng, 0, sizeof(EventEngine));
    eng->port_scan_threshold = cfg->port_scan_threshold;
    eng->port_scan_window    = cfg->port_scan_window;
    eng->dns_tunnel_len      = cfg->dns_tunnel_query_len;
}

/* ============================================================
 * Port Scan Detection
 *
 * Strategy: maintain a fixed-size table indexed by hash(src_ip).
 * On hash collision a new src_ip simply displaces the old entry.
 * This gives O(1) time with no heap allocation at the cost of
 * occasionally missing a detection when two scanners share a hash —
 * an acceptable trade-off for an in-process sensor.
 * ============================================================ */
static uint32_t scan_hash(uint32_t ip) {
    ip ^= (ip >> 16);
    ip *= 0x45d9f3b;
    ip ^= (ip >> 16);
    return ip & SCAN_TABLE_MASK;
}

static void check_port_scan(EventEngine *eng,
                            ConnRecord  *conn,
                            Logger      *log,
                            double       ts) {
    /* Only flag new outbound SYN packets (no reply yet) */
    if (conn->key.proto != PROTO_TCP) return;
    if (conn->state != CONN_STATE_SYN_SENT &&
        conn->state != CONN_STATE_NEW) return;
    /* Only the first packet in a flow triggers this */
    if (conn->orig.pkts != 1) return;

    uint32_t idx   = scan_hash(conn->key.src_ip);
    ScanEntry *ent = &eng->scan_table[idx];

    /* Reset if this slot belongs to a different IP or window expired */
    if (ent->src_ip != conn->key.src_ip ||
        (ts - ent->window_start) > (double)eng->port_scan_window) {
        memset(ent, 0, sizeof(ScanEntry));
        ent->src_ip       = conn->key.src_ip;
        ent->window_start = ts;
    }

    /* Check if destination port already tracked */
    bool already = false;
    for (int i = 0; i < ent->port_count; i++) {
        if (ent->ports[i] == conn->key.dst_port) { already = true; break; }
    }
    if (!already && ent->port_count < SCAN_MAX_PORTS)
        ent->ports[ent->port_count++] = conn->key.dst_port;

    /* Fire notice once per window when threshold crossed */
    if (!ent->reported && ent->port_count >= eng->port_scan_threshold) {
        ent->reported = true;
        eng->notices_generated++;

        char msg[256], sub[64];
        snprintf(msg, sizeof(msg),
            "Port scan: %s contacted %d unique destination ports "
            "in %d second window",
            conn->src_ip_str, ent->port_count, eng->port_scan_window);
        snprintf(sub, sizeof(sub), "%d ports", ent->port_count);

        logger_write_notice(log, ts, conn->uid,
            conn->src_ip_str, conn->key.src_port,
            conn->dst_ip_str, conn->key.dst_port,
            "Scan::Port_Scan", msg, sub);
    }
}

/* ============================================================
 * Brute Force Detection
 * ============================================================ */
static const uint16_t BRUTE_PORTS[] = {
    21, 22, 23, 25, 110, 143, 389, 443, 445,
    993, 995, 1433, 3306, 3389, 5432, 5985, 5986, 0
};

static bool is_auth_port(uint16_t port) {
    for (int i = 0; BRUTE_PORTS[i]; i++)
        if (BRUTE_PORTS[i] == port) return true;
    return false;
}

static uint32_t brute_hash(uint32_t src, uint32_t dst, uint16_t port) {
    uint32_t h = src ^ (dst * 2654435761u) ^ ((uint32_t)port << 16);
    h ^= h >> 16;
    return h & BRUTE_TABLE_MASK;
}

static void check_brute_force(EventEngine *eng,
                               ConnRecord  *conn,
                               Logger      *log,
                               double       ts) {
    if (conn->key.proto != PROTO_TCP) return;
    if (!is_auth_port(conn->key.dst_port)) return;
    if (conn->orig.pkts != 1) return;   /* Count only new flows */

    uint32_t idx   = brute_hash(conn->key.src_ip,
                                 conn->key.dst_ip,
                                 conn->key.dst_port);
    BruteEntry *ent = &eng->brute_table[idx];

    /* Reset on mismatch or window expiry */
    if (ent->src_ip   != conn->key.src_ip  ||
        ent->dst_ip   != conn->key.dst_ip  ||
        ent->dst_port != conn->key.dst_port ||
        (ts - ent->window_start) > BRUTE_WINDOW) {
        memset(ent, 0, sizeof(BruteEntry));
        ent->src_ip      = conn->key.src_ip;
        ent->dst_ip      = conn->key.dst_ip;
        ent->dst_port    = conn->key.dst_port;
        ent->window_start = ts;
    }

    ent->attempt_count++;

    if (!ent->reported && ent->attempt_count >= BRUTE_THRESHOLD) {
        ent->reported = true;
        eng->notices_generated++;

        char msg[256], sub[64];
        snprintf(msg, sizeof(msg),
            "Brute force: %s made %d connection attempts to %s port %u "
            "within %.0fs",
            conn->src_ip_str, ent->attempt_count,
            conn->dst_ip_str, (unsigned)conn->key.dst_port,
            BRUTE_WINDOW);
        snprintf(sub, sizeof(sub), "%d attempts", ent->attempt_count);

        logger_write_notice(log, ts, conn->uid,
            conn->src_ip_str, conn->key.src_port,
            conn->dst_ip_str, conn->key.dst_port,
            "Brute::Force_Attempt", msg, sub);
    }
}

/* ============================================================
 * DNS Tunneling Detection
 * ============================================================ */
static void check_dns_tunnel(EventEngine *eng,
                              ConnRecord  *conn,
                              Logger      *log,
                              double       ts) {
    if (!conn->app.dns_detected || !conn->app.dns_query_seen) return;
    const ParsedDNS *q = &conn->app.dns_query;

    int qlen = (int)strlen(q->query);

    /* Long query name */
    if (qlen >= eng->dns_tunnel_len) {
        eng->notices_generated++;
        char msg[512], sub[64];
        snprintf(msg, sizeof(msg),
            "Possible DNS tunneling: query name length %d exceeds "
            "threshold %d — query: %.120s",
            qlen, eng->dns_tunnel_len, q->query);
        snprintf(sub, sizeof(sub), "len=%d", qlen);

        logger_write_notice(log, ts, conn->uid,
            conn->src_ip_str, conn->key.src_port,
            conn->dst_ip_str, conn->key.dst_port,
            "DNS::Tunneling", msg, sub);
    }

    /* Excessive subdomain depth (>= 5 labels) */
    int dots = 0;
    for (const char *p = q->query; *p; p++)
        if (*p == '.') dots++;

    if (dots >= 5) {
        eng->weirds_generated++;
        logger_write_weird(log, ts, conn->uid,
            conn->src_ip_str, conn->key.src_port,
            conn->dst_ip_str, conn->key.dst_port,
            "excessive_dns_labels", q->query);
    }
}

/* ============================================================
 * TLS/SSL Anomaly Detection
 * ============================================================ */
static void check_tls(EventEngine *eng,
                      ConnRecord  *conn,
                      Logger      *log,
                      double       ts) {
    if (!conn->app.tls_detected) return;
    const TLSSession *tls = &conn->app.tls;

    /* Self-signed certificate */
    if (tls->certificate.is_valid && tls->certificate.self_signed) {
        eng->notices_generated++;
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Self-signed TLS certificate presented by %s (SNI: %s)",
            conn->dst_ip_str,
            tls->client_hello.sni[0] ? tls->client_hello.sni : "(none)");

        logger_write_notice(log, ts, conn->uid,
            conn->src_ip_str, conn->key.src_port,
            conn->dst_ip_str, conn->key.dst_port,
            "SSL::Self_Signed_Cert", msg, NULL);
    }

    /* Deprecated protocol version (SSLv3 = 0x0300, TLS 1.0 = 0x0301) */
    uint16_t ver = tls->server_hello.version
                   ? tls->server_hello.version
                   : tls->client_hello.version;
    if (ver == 0x0300 || ver == 0x0301) {
        eng->weirds_generated++;
        char addl[64];
        snprintf(addl, sizeof(addl), "version=%s", tls_version_str(ver));
        logger_write_weird(log, ts, conn->uid,
            conn->src_ip_str, conn->key.src_port,
            conn->dst_ip_str, conn->key.dst_port,
            "deprecated_ssl_version", addl);
    }

    (void)eng;
}

/* ============================================================
 * HTTP Anomaly Detection
 * ============================================================ */
static void check_http(EventEngine *eng,
                       ConnRecord  *conn,
                       Logger      *log,
                       double       ts) {
    if (!conn->app.http_detected || !conn->app.http_req_seen) return;
    const HTTPRequest *req = &conn->app.http_req;

    /* Cleartext HTTP Basic Authentication */
    if (req->authorization[0] &&
        strncmp(req->authorization, "Basic ", 6) == 0) {
        eng->notices_generated++;
        char msg[256];
        snprintf(msg, sizeof(msg),
            "HTTP Basic Auth credentials sent in cleartext to %s:%u "
            "(URI: %.80s)",
            conn->dst_ip_str, (unsigned)conn->key.dst_port, req->uri);

        logger_write_notice(log, ts, conn->uid,
            conn->src_ip_str, conn->key.src_port,
            conn->dst_ip_str, conn->key.dst_port,
            "HTTP::Cleartext_Auth", msg, NULL);
    }

    /* Missing User-Agent (common in automated tools / malware) */
    if (!req->user_agent[0]) {
        eng->weirds_generated++;
        logger_write_weird(log, ts, conn->uid,
            conn->src_ip_str, conn->key.src_port,
            conn->dst_ip_str, conn->key.dst_port,
            "missing_user_agent",
            req->uri[0] ? req->uri : "(no URI)");
    }

    /* Unusually long URI (potential SQL-injection / path traversal probe) */
    if ((int)strlen(req->uri) > 1024) {
        eng->notices_generated++;
        char msg[256];
        snprintf(msg, sizeof(msg),
            "Unusually long HTTP URI (%d chars) to %s:%u",
            (int)strlen(req->uri),
            conn->dst_ip_str, (unsigned)conn->key.dst_port);

        logger_write_notice(log, ts, conn->uid,
            conn->src_ip_str, conn->key.src_port,
            conn->dst_ip_str, conn->key.dst_port,
            "HTTP::Long_URI", msg, req->uri);
    }

    (void)eng;
}

/* ============================================================
 * Public: Per-packet analysis  (called from main loop)
 * ============================================================ */
void event_engine_analyze(EventEngine *eng,
                          ConnRecord  *conn,
                          Logger      *log,
                          double       ts) {
    check_port_scan(eng,   conn, log, ts);
    check_brute_force(eng, conn, log, ts);

    /* Application-layer checks only once we have payload data */
    if (conn->app.dns_detected)  check_dns_tunnel(eng, conn, log, ts);
    if (conn->app.http_detected) check_http(eng,       conn, log, ts);
    if (conn->app.tls_detected)  check_tls(eng,        conn, log, ts);
}

/* ============================================================
 * Public: On connection close  (called from expiry callback)
 * Writes application-layer log records and runs final checks.
 * ============================================================ */
void event_engine_on_close(EventEngine *eng,
                           ConnRecord  *conn,
                           Logger      *log,
                           double       ts) {
    /* DNS log — only log residual query-without-response.
     * Complete query+response transactions are already logged
     * inline by classify_application() in main.c.              */
    if (conn->app.dns_detected &&
        conn->app.dns_query_seen && !conn->app.dns_resp_seen) {
        logger_write_dns(log, conn,
            &conn->app.dns_query, NULL);
    }

    /* HTTP log */
    if (conn->app.http_detected && conn->app.http_req_seen) {
        logger_write_http(log, conn,
            &conn->app.http_req,
            conn->app.http_resp_seen ? &conn->app.http_resp : NULL);
    }

    /* SSL log */
    if (conn->app.tls_detected) {
        logger_write_ssl(log, conn, &conn->app.tls);

        /* Generate synthetic dns.log from TLS SNI so that HTTPS
         * website visits always appear in dns.log — even when
         * the browser used DNS-over-HTTPS (encrypted DNS).       */
        const char *sni = conn->app.tls.client_hello.sni;
        if (sni[0] && !conn->app.dns_detected) {
            logger_write_dns_from_sni(log, conn, sni);
        }
    }

    /* Run any last checks that need the full flow view */
    check_dns_tunnel(eng, conn, log, ts);
    check_http(eng,       conn, log, ts);
    check_tls(eng,        conn, log, ts);

    (void)ts;
}

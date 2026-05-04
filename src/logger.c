/*
 * logger.c - Zeek-Compatible JSON Log Writer Implementation
 *
 * JSON format: each record is a single line (NDJSON / JSON-Lines).
 * All string values are JSON-escaped.  Timestamps are Unix epoch
 * in decimal seconds with 6 decimal places, matching Zeek's format.
 */

#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================
 * Internal: JSON string escaping
 * ============================================================ */
static void json_escape(const char *in, char *out, int outlen) {
    int j = 0;
    for (int i = 0; in && in[i] && j < outlen - 4; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
        case '"':  out[j++] = '\\'; out[j++] = '"';  break;
        case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
        case '\n': out[j++] = '\\'; out[j++] = 'n';  break;
        case '\r': out[j++] = '\\'; out[j++] = 'r';  break;
        case '\t': out[j++] = '\\'; out[j++] = 't';  break;
        default:
            if (c >= 0x20) out[j++] = (char)c;
            /* skip raw control characters */
            break;
        }
    }
    out[j] = '\0';
}

/* Thread-local escape buffer (single-shot, not re-entrant safe within
 * a single snprintf call — use separate buffers per field if needed) */
static char _jbuf[4096];
static const char *jstr(const char *s) {
    if (!s) { _jbuf[0] = '\0'; return _jbuf; }
    json_escape(s, _jbuf, sizeof(_jbuf));
    return _jbuf;
}

/* ============================================================
 * Internal: open / close a single log file
 * ============================================================ */
static const char *log_names[LOG_COUNT] = {
    "conn", "dns", "http", "ssl", "notice", "weird", "stats"
};

static int open_log_file(LogFile *lf, const char *dir, const char *name, double ts) {
    snprintf(lf->path, sizeof(lf->path), "%s\\%s.log", dir, name);

    lf->fp            = fopen(lf->path, "a");
    lf->bytes_written = 0;
    lf->open_ts       = ts;
    return lf->fp ? 0 : -1;
}

static void close_log_file(LogFile *lf) {
    if (lf->fp) {
        fflush(lf->fp);
        fclose(lf->fp);
        lf->fp = NULL;
    }
}

/* ============================================================
 * logger_init
 * ============================================================ */
int logger_init(Logger *log,
                const char *log_dir,
                int         rotation_interval,
                int64_t     max_file_size,
                bool        enable_conn,
                bool        enable_dns,
                bool        enable_http,
                bool        enable_ssl,
                bool        enable_notice,
                bool        enable_weird,
                bool        enable_stats) {
    memset(log, 0, sizeof(Logger));

    strncpy(log->log_dir, log_dir, sizeof(log->log_dir) - 1);
    log->rotation_interval = rotation_interval;
    log->max_file_size     = max_file_size;
    log->enable_conn       = enable_conn;
    log->enable_dns        = enable_dns;
    log->enable_http       = enable_http;
    log->enable_ssl        = enable_ssl;
    log->enable_notice     = enable_notice;
    log->enable_weird      = enable_weird;
    log->enable_stats      = enable_stats;

    /* Create log directory (recursive not needed — assume parent exists) */
    CreateDirectoryA(log_dir, NULL);

    /* Create mutex for thread safety */
    log->mutex = CreateMutexA(NULL, FALSE, NULL);
    if (!log->mutex) {
        fprintf(stderr, "[logger] CreateMutex failed: %lu\n", GetLastError());
        return -1;
    }

    double now = get_timestamp();
    log->last_rotation = now;

    bool enables[LOG_COUNT] = {
        enable_conn, enable_dns, enable_http, enable_ssl,
        enable_notice, enable_weird, enable_stats
    };
    for (int i = 0; i < LOG_COUNT; i++) {
        if (!enables[i]) continue;
        if (open_log_file(&log->files[i], log_dir, log_names[i], now) != 0) {
            fprintf(stderr, "[logger] Failed to open %s.log in: %s\n",
                    log_names[i], log_dir);
        } else {
            fprintf(stdout, "[logger] Opened: %s\n", log->files[i].path);
        }
    }
    return 0;
}

/* ============================================================
 * logger_close
 * ============================================================ */
void logger_close(Logger *log) {
    for (int i = 0; i < LOG_COUNT; i++)
        close_log_file(&log->files[i]);

    if (log->mutex) {
        CloseHandle(log->mutex);
        log->mutex = NULL;
    }
}

/* ============================================================
 * logger_rotate_if_needed
 * ============================================================ */
void logger_rotate_if_needed(Logger *log, double now) {
    bool time_expired = log->rotation_interval > 0 &&
                        (now - log->last_rotation) >= (double)log->rotation_interval;

    /* Check size limit on any open file */
    bool size_hit = false;
    if (log->max_file_size > 0) {
        for (int i = 0; i < LOG_COUNT; i++) {
            if (log->files[i].fp &&
                log->files[i].bytes_written >= log->max_file_size) {
                size_hit = true;
                break;
            }
        }
    }

    if (!time_expired && !size_hit) return;

    WaitForSingleObject(log->mutex, INFINITE);
    log->last_rotation = now;

    bool enables[LOG_COUNT] = {
        log->enable_conn, log->enable_dns, log->enable_http, log->enable_ssl,
        log->enable_notice, log->enable_weird, log->enable_stats
    };
    for (int i = 0; i < LOG_COUNT; i++) {
        if (!enables[i]) continue;
        
        LogFile *lf = &log->files[i];
        if (lf->fp) {
            /* Close the file handle so we can rename it */
            fclose(lf->fp);
            lf->fp = NULL;

            /* Rename old file to include its starting timestamp */
            time_t t = (time_t)lf->open_ts;
            struct tm *tm_info = gmtime(&t);
            char stamp[32] = "unknown";
            if (tm_info) strftime(stamp, sizeof(stamp), "%Y-%m-%d_%H-%M-%S", tm_info);
            
            char rotated_path[1024];
            snprintf(rotated_path, sizeof(rotated_path), "%s\\%s_%s.log", log->log_dir, log_names[i], stamp);
            
            /* Perform the rename (rotation) */
            rename(lf->path, rotated_path);
        }

        /* Open a brand new file with the clean name (e.g., conn.log) */
        open_log_file(lf, log->log_dir, log_names[i], now);
    }
    fprintf(stdout, "[logger] Log files rotated.\n");
    ReleaseMutex(log->mutex);
}

/* ============================================================
 * Internal: write one JSON line to a log stream
 * ============================================================ */
static void log_writeln(Logger *log, LogType type, const char *line) {
    LogFile *lf = &log->files[type];
    if (!lf->fp) return;

    WaitForSingleObject(log->mutex, INFINITE);
    int n = fprintf(lf->fp, "%s\n", line);
    if (n > 0) lf->bytes_written += (int64_t)n;
    fflush(lf->fp);
    ReleaseMutex(log->mutex);
}

/* ============================================================
 * conn.log
 *
 * Zeek schema (subset):
 *   ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p
 *   proto  service  duration
 *   orig_bytes  resp_bytes  conn_state
 *   orig_pkts   resp_pkts   orig_ip_bytes  resp_ip_bytes
 * ============================================================ */
void logger_write_conn(Logger *log, const ConnRecord *conn) {
    if (!log->enable_conn) return;

    char buf[1024];
    snprintf(buf, sizeof(buf),
        "{\"ts\":%.6f,\"uid\":\"%s\","
        "\"id.orig_h\":\"%s\",\"id.orig_p\":%u,"
        "\"id.resp_h\":\"%s\",\"id.resp_p\":%u,"
        "\"proto\":\"%s\",\"service\":\"%s\","
        "\"duration\":%.6f,"
        "\"orig_bytes\":%llu,\"resp_bytes\":%llu,"
        "\"conn_state\":\"%s\","
        "\"orig_pkts\":%llu,\"resp_pkts\":%llu,"
        "\"orig_ip_bytes\":%llu,\"resp_ip_bytes\":%llu}",
        conn->ts_start,
        conn->uid,
        conn->src_ip_str,  (unsigned)conn->key.src_port,
        conn->dst_ip_str,  (unsigned)conn->key.dst_port,
        proto_name(conn->key.proto),
        conn->service[0] ? conn->service : "-",
        conn->duration,
        (unsigned long long)conn->orig.bytes,
        (unsigned long long)conn->resp.bytes,
        conn_state_str(conn),
        (unsigned long long)conn->orig.pkts,
        (unsigned long long)conn->resp.pkts,
        (unsigned long long)conn->orig.bytes,
        (unsigned long long)conn->resp.bytes
    );
    log_writeln(log, LOG_CONN, buf);
}

/* ============================================================
 * dns.log
 *
 * Zeek schema (subset):
 *   ts  uid  id.*  proto  trans_id  rtt  query
 *   qclass  qclass_name  qtype  qtype_name
 *   rcode  rcode_name  AA TC RD RA  rejected  answers  TTLs
 * ============================================================ */
void logger_write_dns(Logger *log,
                      const ConnRecord *conn,
                      const ParsedDNS  *query,
                      const ParsedDNS  *response) {
    if (!log->enable_dns) return;

    /* Choose the most informative record */
    const ParsedDNS *d = response ? response : query;
    if (!d || !d->is_valid) return;

    char qesc[DNS_MAX_NAME_LEN * 2];
    char aesc[sizeof(d->answers_str) * 2];
    json_escape(d->query,       qesc, sizeof(qesc));
    json_escape(d->answers_str, aesc, sizeof(aesc));

    double rtt = (query && response) ? (conn->ts_last - conn->ts_start) : 0.0;

    char buf[4096];
    snprintf(buf, sizeof(buf),
        "{\"ts\":%.6f,\"uid\":\"%s\","
        "\"id.orig_h\":\"%s\",\"id.orig_p\":%u,"
        "\"id.resp_h\":\"%s\",\"id.resp_p\":%u,"
        "\"proto\":\"%s\","
        "\"trans_id\":%u,\"rtt\":%.6f,"
        "\"query\":\"%s\","
        "\"qclass\":%u,\"qclass_name\":\"%s\","
        "\"qtype\":%u,\"qtype_name\":\"%s\","
        "\"rcode\":%d,\"rcode_name\":\"%s\","
        "\"AA\":%s,\"TC\":%s,\"RD\":%s,\"RA\":%s,"
        "\"rejected\":%s,"
        "\"answers\":\"%s\",\"TTLs\":\"%s\"}",
        conn->ts_start, conn->uid,
        conn->src_ip_str, (unsigned)conn->key.src_port,
        conn->dst_ip_str, (unsigned)conn->key.dst_port,
        proto_name(conn->key.proto),
        (unsigned)d->trans_id, rtt,
        qesc,
        (unsigned)d->qclass, d->qclass_name,
        (unsigned)d->qtype,  d->qtype_name,
        d->rcode, d->rcode_name,
        d->authoritative       ? "true" : "false",
        d->truncated           ? "true" : "false",
        d->recursion_desired   ? "true" : "false",
        d->recursion_available ? "true" : "false",
        d->rejected            ? "true" : "false",
        aesc, d->ttls_str
    );
    log_writeln(log, LOG_DNS, buf);
}

/* ============================================================
 * http.log
 *
 * Zeek schema (subset):
 *   ts  uid  id.*  trans_depth  method  host  uri  referrer
 *   version  user_agent  request_body_len  response_body_len
 *   status_code  status_msg  resp_mime_types
 * ============================================================ */
void logger_write_http(Logger        *log,
                       const ConnRecord   *conn,
                       const HTTPRequest  *req,
                       const HTTPResponse *resp) {
    if (!log->enable_http || !req || !req->is_valid) return;

    char uri[HTTP_MAX_URI  * 2];
    char ua [HTTP_MAX_HEADER_VAL * 2];
    char host[HTTP_MAX_HOST * 2];
    char ref [HTTP_MAX_HEADER_VAL * 2];
    json_escape(req->uri,        uri,  sizeof(uri));
    json_escape(req->user_agent, ua,   sizeof(ua));
    json_escape(req->host,       host, sizeof(host));
    json_escape(req->referer,    ref,  sizeof(ref));

    char mime[HTTP_MAX_HEADER_VAL * 2];
    json_escape(resp ? resp->content_type : "", mime, sizeof(mime));

    char buf[4096];
    snprintf(buf, sizeof(buf),
        "{\"ts\":%.6f,\"uid\":\"%s\","
        "\"id.orig_h\":\"%s\",\"id.orig_p\":%u,"
        "\"id.resp_h\":\"%s\",\"id.resp_p\":%u,"
        "\"trans_depth\":1,"
        "\"method\":\"%s\","
        "\"host\":\"%s\","
        "\"uri\":\"%s\","
        "\"referrer\":\"%s\","
        "\"version\":\"%s\","
        "\"user_agent\":\"%s\","
        "\"request_body_len\":%d,"
        "\"response_body_len\":%d,"
        "\"status_code\":%d,"
        "\"status_msg\":\"%s\","
        "\"resp_mime_types\":\"%s\"}",
        conn->ts_start, conn->uid,
        conn->src_ip_str, (unsigned)conn->key.src_port,
        conn->dst_ip_str, (unsigned)conn->key.dst_port,
        req->method[0]  ? req->method  : "-",
        host,
        uri,
        ref,
        req->version[0] ? req->version : "-",
        ua,
        req->content_length  > 0 ? req->content_length  : 0,
        resp && resp->content_length > 0 ? resp->content_length : 0,
        resp ? resp->status_code : 0,
        resp && resp->status_msg[0] ? jstr(resp->status_msg) : "-",
        mime[0] ? mime : "-"
    );
    log_writeln(log, LOG_HTTP, buf);
}

/* ============================================================
 * ssl.log
 *
 * Zeek schema (subset):
 *   ts  uid  id.*  version  cipher  server_name
 *   established  resumed  ja3  ja3s  next_protocol
 * ============================================================ */
void logger_write_ssl(Logger *log,
                      const ConnRecord *conn,
                      const TLSSession *tls) {
    if (!log->enable_ssl || !tls) return;

    const TLSClientHello *ch = &tls->client_hello;
    const TLSServerHello *sh = &tls->server_hello;

    char sni[TLS_MAX_SNI * 2];
    json_escape(ch->sni, sni, sizeof(sni));

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{\"ts\":%.6f,\"uid\":\"%s\","
        "\"id.orig_h\":\"%s\",\"id.orig_p\":%u,"
        "\"id.resp_h\":\"%s\",\"id.resp_p\":%u,"
        "\"version\":\"%s\","
        "\"cipher\":\"%s\","
        "\"server_name\":\"%s\","
        "\"established\":%s,"
        "\"resumed\":%s,"
        "\"ja3\":\"%s\","
        "\"ja3s\":\"%s\","
        "\"next_protocol\":\"%s\"}",
        conn->ts_start, conn->uid,
        conn->src_ip_str, (unsigned)conn->key.src_port,
        conn->dst_ip_str, (unsigned)conn->key.dst_port,
        tls_version_str(sh->version ? sh->version : ch->version),
        tls_cipher_str(sh->cipher_suite),
        sni[0] ? sni : "-",
        tls->established ? "true" : "false",
        tls->resumed     ? "true" : "false",
        ch->ja3_hash[0]  ? ch->ja3_hash  : "-",
        sh->ja3s_hash[0] ? sh->ja3s_hash : "-",
        ch->alpn[0]      ? ch->alpn      : "-"
    );
    log_writeln(log, LOG_SSL, buf);
}

/* ============================================================
 * notice.log
 *
 * Zeek schema (subset):
 *   ts  uid  id.*  note  msg  sub  actions
 * ============================================================ */
void logger_write_notice(Logger     *log,
                         double      ts,
                         const char *uid,
                         const char *src_ip,  uint16_t src_port,
                         const char *dst_ip,  uint16_t dst_port,
                         const char *note,
                         const char *msg,
                         const char *sub) {
    if (!log->enable_notice) return;

    char msg_esc[2048], sub_esc[512];
    json_escape(msg, msg_esc, sizeof(msg_esc));
    json_escape(sub ? sub : "", sub_esc, sizeof(sub_esc));

    char buf[4096];
    snprintf(buf, sizeof(buf),
        "{\"ts\":%.6f,\"uid\":\"%s\","
        "\"id.orig_h\":\"%s\",\"id.orig_p\":%u,"
        "\"id.resp_h\":\"%s\",\"id.resp_p\":%u,"
        "\"note\":\"%s\","
        "\"msg\":\"%s\","
        "\"sub\":\"%s\","
        "\"actions\":[\"Notice::ACTION_LOG\"]}",
        ts,
        uid     ? uid     : "-",
        src_ip  ? src_ip  : "-", (unsigned)src_port,
        dst_ip  ? dst_ip  : "-", (unsigned)dst_port,
        note    ? note    : "-",
        msg_esc,
        sub_esc
    );
    log_writeln(log, LOG_NOTICE, buf);
}

/* ============================================================
 * weird.log
 *
 * Zeek schema (subset):
 *   ts  uid  id.*  name  addl  notice
 * ============================================================ */
void logger_write_weird(Logger     *log,
                        double      ts,
                        const char *uid,
                        const char *src_ip,  uint16_t src_port,
                        const char *dst_ip,  uint16_t dst_port,
                        const char *name,
                        const char *addl) {
    if (!log->enable_weird) return;

    char addl_esc[1024];
    json_escape(addl ? addl : "", addl_esc, sizeof(addl_esc));

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{\"ts\":%.6f,\"uid\":\"%s\","
        "\"id.orig_h\":\"%s\",\"id.orig_p\":%u,"
        "\"id.resp_h\":\"%s\",\"id.resp_p\":%u,"
        "\"name\":\"%s\","
        "\"addl\":\"%s\","
        "\"notice\":false}",
        ts,
        uid    ? uid    : "-",
        src_ip ? src_ip : "-", (unsigned)src_port,
        dst_ip ? dst_ip : "-", (unsigned)dst_port,
        name   ? name   : "-",
        addl_esc
    );
    log_writeln(log, LOG_WEIRD, buf);
}

/* ============================================================
 * stats.log
 *
 * Zeek schema (subset):
 *   ts  peer  mem  pkts_proc  bytes_recv  pkts_dropped
 *   pkts_link  pkt_lag  active_tcp_conns  ...
 * ============================================================ */
void logger_write_stats(Logger   *log,
                        double    ts,
                        int       active_conns,
                        uint64_t  pkts_recv,
                        uint64_t  pkts_drop,
                        uint64_t  bytes_recv) {
    if (!log->enable_stats) return;

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"ts\":%.6f,\"peer\":\"zeek-nsm\","
        "\"pkts_proc\":%llu,"
        "\"bytes_recv\":%llu,"
        "\"pkts_dropped\":%llu,"
        "\"pkts_link\":%llu,"
        "\"pkt_lag\":0.000000,"
        "\"active_conns\":%d}",
        ts,
        (unsigned long long)pkts_recv,
        (unsigned long long)bytes_recv,
        (unsigned long long)pkts_drop,
        (unsigned long long)pkts_recv,
        active_conns
    );
    log_writeln(log, LOG_STATS, buf);
}

/* ============================================================
 * dns.log from TLS SNI  (synthetic entry)
 *
 * When a browser uses DNS-over-HTTPS we never see the port-53
 * query, but the TLS ClientHello still leaks the hostname via
 * SNI.  Write a dns.log record with:
 *   query        = SNI hostname
 *   answers      = connection destination IP
 *   qtype_name   = "SNI"        (distinguishes from real DNS)
 *   rcode_name   = "NOERROR"
 * ============================================================ */
void logger_write_dns_from_sni(Logger *log,
                                const ConnRecord *conn,
                                const char *sni) {
    if (!log->enable_dns || !sni || !sni[0]) return;

    char sni_esc[512];
    json_escape(sni, sni_esc, sizeof(sni_esc));

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{\"ts\":%.6f,\"uid\":\"%s\","
        "\"id.orig_h\":\"%s\",\"id.orig_p\":%u,"
        "\"id.resp_h\":\"%s\",\"id.resp_p\":%u,"
        "\"proto\":\"tcp\","
        "\"trans_id\":0,\"rtt\":0.000000,"
        "\"query\":\"%s\","
        "\"qclass\":1,\"qclass_name\":\"C_INTERNET\","
        "\"qtype\":1,\"qtype_name\":\"SNI\","
        "\"rcode\":0,\"rcode_name\":\"NOERROR\","
        "\"AA\":false,\"TC\":false,\"RD\":false,\"RA\":false,"
        "\"rejected\":false,"
        "\"answers\":\"%s\",\"TTLs\":\"0\"}",
        conn->ts_start, conn->uid,
        conn->src_ip_str, (unsigned)conn->key.src_port,
        conn->dst_ip_str, (unsigned)conn->key.dst_port,
        sni_esc,
        conn->dst_ip_str
    );
    log_writeln(log, LOG_DNS, buf);
}

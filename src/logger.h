/*
 * logger.h - Zeek-Compatible JSON Log Writer
 *
 * Writes newline-delimited JSON to per-stream log files:
 *   conn.log   – one record per closed connection (Zeek conn.log schema)
 *   dns.log    – DNS queries/responses
 *   http.log   – HTTP request+response pairs
 *   ssl.log    – TLS/SSL sessions with JA3/JA3S fingerprints
 *   notice.log – Detections raised by the event engine
 *   weird.log  – Protocol anomalies
 *   stats.log  – Periodic capture statistics
 *
 * Log rotation is time-based (rotation_interval) and size-based
 * (max_file_size). A Windows Mutex guards all file I/O so the
 * logger is safe to call from multiple threads.
 */

#ifndef ZEEK_LOGGER_H
#define ZEEK_LOGGER_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

#include "conn_tracker.h"
#include "config.h"

/* ============================================================
 * Log Stream Identifiers
 * ============================================================ */
typedef enum {
    LOG_CONN   = 0,
    LOG_DNS    = 1,
    LOG_HTTP   = 2,
    LOG_SSL    = 3,
    LOG_NOTICE = 4,
    LOG_WEIRD  = 5,
    LOG_STATS  = 6,
    LOG_COUNT  = 7
} LogType;

/* ============================================================
 * Individual Log File Handle
 * ============================================================ */
typedef struct {
    FILE    *fp;
    char     path[MAX_PATH_LEN];
    int64_t  bytes_written;    /* Bytes since this file was opened */
    double   open_ts;          /* Timestamp when file was opened */
} LogFile;

/* ============================================================
 * Logger Context
 * ============================================================ */
typedef struct {
    LogFile  files[LOG_COUNT];

    char     log_dir[MAX_PATH_LEN];
    int      rotation_interval;    /* Seconds between rotations; 0 = never */
    int64_t  max_file_size;        /* Rotate on size (bytes); 0 = no limit */
    double   last_rotation;        /* Timestamp of last rotation */

    HANDLE   mutex;                /* Serialises all file writes */

    bool     enable_conn;
    bool     enable_dns;
    bool     enable_http;
    bool     enable_ssl;
    bool     enable_notice;
    bool     enable_weird;
    bool     enable_stats;
} Logger;

/* ============================================================
 * Lifecycle
 * ============================================================ */

/* Initialise logger: create log_dir, open all enabled files. Returns 0 on success. */
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
                bool        enable_stats);

/* Flush and close all log files; destroy mutex. */
void logger_close(Logger *log);

/* Rotate log files if rotation_interval has elapsed or max_file_size exceeded. */
void logger_rotate_if_needed(Logger *log, double now);

/* ============================================================
 * Per-Stream Writers
 * ============================================================ */

/* Write a connection record to conn.log (called on flow expiry). */
void logger_write_conn(Logger *log, const ConnRecord *conn);

/* Write a DNS transaction to dns.log. Pass NULL for query or response if absent. */
void logger_write_dns(Logger *log,
                      const ConnRecord *conn,
                      const ParsedDNS  *query,
                      const ParsedDNS  *response);

/* Write an HTTP request+response pair to http.log. resp may be NULL. */
void logger_write_http(Logger       *log,
                       const ConnRecord  *conn,
                       const HTTPRequest *req,
                       const HTTPResponse *resp);

/* Write a TLS/SSL session to ssl.log. */
void logger_write_ssl(Logger *log,
                      const ConnRecord *conn,
                      const TLSSession *tls);

/* Write a detection notice to notice.log. sub may be NULL. */
void logger_write_notice(Logger     *log,
                         double      ts,
                         const char *uid,
                         const char *src_ip,   uint16_t src_port,
                         const char *dst_ip,   uint16_t dst_port,
                         const char *note,
                         const char *msg,
                         const char *sub);

/* Write a protocol anomaly to weird.log. addl may be NULL. */
void logger_write_weird(Logger     *log,
                        double      ts,
                        const char *uid,
                        const char *src_ip,   uint16_t src_port,
                        const char *dst_ip,   uint16_t dst_port,
                        const char *name,
                        const char *addl);

/* Write periodic capture statistics to stats.log. */
void logger_write_stats(Logger   *log,
                        double    ts,
                        int       active_conns,
                        uint64_t  pkts_recv,
                        uint64_t  pkts_drop,
                        uint64_t  bytes_recv);
/* Write a synthetic DNS entry derived from TLS SNI observation.
 * This ensures HTTPS site visits appear in dns.log even when the
 * browser used DNS-over-HTTPS and we never saw a port-53 query. */
void logger_write_dns_from_sni(Logger *log,
                                const ConnRecord *conn,
                                const char *sni);

#endif /* ZEEK_LOGGER_H */

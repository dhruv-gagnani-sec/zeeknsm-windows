/*
 * event_engine.h - Real-Time Detection Event Engine
 *
 * Implements Zeek-style behavioral detection:
 *
 *   Port Scan Detection
 *     Fires Scan::Port_Scan notice when a single source IP contacts
 *     more than port_scan_threshold unique destination ports within
 *     port_scan_window seconds.
 *
 *   Brute Force Detection
 *     Fires Brute::Force_Attempt notice when a source IP makes 10+
 *     new connections to the same service port within 60 seconds.
 *
 *   DNS Tunneling Detection
 *     Fires DNS::Tunneling notice when a query name exceeds
 *     dns_tunnel_query_len characters, and a weird for deeply
 *     nested subdomain labels (>= 5 dots).
 *
 *   TLS/SSL Anomaly Detection
 *     SSL::Self_Signed_Cert notice for self-signed certificates.
 *     weird for deprecated SSL 3.0 / TLS 1.0 usage.
 *
 *   HTTP Anomaly Detection
 *     HTTP::Cleartext_Auth notice for Basic auth over plain HTTP.
 *     weird for missing User-Agent headers.
 */

#ifndef ZEEK_EVENT_ENGINE_H
#define ZEEK_EVENT_ENGINE_H

#include <stdint.h>
#include <stdbool.h>
#include "conn_tracker.h"
#include "logger.h"
#include "config.h"

/* ============================================================
 * Port Scan Tracking  (one entry per source IP, LRU-evicted)
 * ============================================================ */
#define SCAN_TABLE_SIZE   4096
#define SCAN_TABLE_MASK   (SCAN_TABLE_SIZE - 1)
#define SCAN_MAX_PORTS    256

typedef struct {
    uint32_t src_ip;
    double   window_start;
    uint16_t ports[SCAN_MAX_PORTS];
    int      port_count;
    bool     reported;
} ScanEntry;

/* ============================================================
 * Brute Force Tracking  (per src_ip + dst_ip + dst_port)
 * ============================================================ */
#define BRUTE_TABLE_SIZE  1024
#define BRUTE_TABLE_MASK  (BRUTE_TABLE_SIZE - 1)
#define BRUTE_THRESHOLD   10      /* attempts within BRUTE_WINDOW */
#define BRUTE_WINDOW      60.0    /* seconds */

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    double   window_start;
    int      attempt_count;
    bool     reported;
} BruteEntry;

/* ============================================================
 * Event Engine Context
 * ============================================================ */
typedef struct {
    ScanEntry  scan_table[SCAN_TABLE_SIZE];
    BruteEntry brute_table[BRUTE_TABLE_SIZE];

    int        port_scan_threshold;
    int        port_scan_window;
    int        dns_tunnel_len;

    uint64_t   notices_generated;
    uint64_t   weirds_generated;
} EventEngine;

/* ============================================================
 * Public API
 * ============================================================ */

/* Initialise engine from loaded configuration. */
void event_engine_init(EventEngine *eng, const ZeekConfig *cfg);

/* Analyse a newly seen or updated flow.
 * Called per-packet for the first few packets in a flow.
 * May write to notice.log and/or weird.log. */
void event_engine_analyze(EventEngine *eng,
                          ConnRecord  *conn,
                          Logger      *log,
                          double       ts);

/* Called when a flow expires / is closed.
 * Writes application-layer log records (dns.log, http.log, ssl.log)
 * and performs final anomaly checks. */
void event_engine_on_close(EventEngine *eng,
                           ConnRecord  *conn,
                           Logger      *log,
                           double       ts);

#endif /* ZEEK_EVENT_ENGINE_H */

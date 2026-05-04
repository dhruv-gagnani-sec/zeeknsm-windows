/*
 * conn_tracker.h - Network Connection State Tracker
 * Tracks TCP/UDP/ICMP flows with Zeek-compatible conn.log fields.
 * Uses a hash table with open chaining for O(1) average-case lookup.
 *
 * Architecture:
 *   ConnTable  -->  ConnRecord[]  (per-flow state)
 *                        |
 *                        +-->  AppState  (TLS / HTTP / DNS layer)
 */

#ifndef ZEEK_CONN_TRACKER_H
#define ZEEK_CONN_TRACKER_H

#include <stdint.h>
#include <stdbool.h>
#include "protocols.h"
#include "tls_parser.h"
#include "http_parser.h"
#include "dns_parser.h"
#include "uid.h"

/* ============================================================
 * Hash table sizing  (must be power of 2)
 * ============================================================ */
#define CONN_TABLE_SIZE  65536
#define CONN_TABLE_MASK  (CONN_TABLE_SIZE - 1)

/* ============================================================
 * TCP State Machine  (Zeek-compatible names)
 * ============================================================ */
typedef enum {
    CONN_STATE_NEW = 0,     /* SYN not yet seen */
    CONN_STATE_SYN_SENT,    /* SYN sent, no reply */
    CONN_STATE_SYN_RECV,    /* SYN+ACK seen */
    CONN_STATE_ESTABLISHED, /* Three-way handshake complete */
    CONN_STATE_FIN_WAIT,    /* FIN seen from one side */
    CONN_STATE_CLOSE_WAIT,  /* Waiting for local close */
    CONN_STATE_CLOSED,      /* Both FINs seen */
    CONN_STATE_RESET,       /* RST seen */
    /* Non-TCP states */
    CONN_STATE_UDP_ACTIVE,
    CONN_STATE_ICMP_ACTIVE,
} ConnState;

/* ============================================================
 * 5-Tuple Connection Key
 * ============================================================ */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} ConnKey;

/* ============================================================
 * Per-direction Traffic Counters
 * ============================================================ */
typedef struct {
    uint64_t bytes;   /* IP-level bytes */
    uint64_t pkts;    /* Packet count */
    bool     fin;     /* FIN seen from this side */
    bool     rst;     /* RST seen from this side */
} ConnDir;

/* ============================================================
 * Application-Layer State
 * Populated by the classifier in main.c as payloads arrive.
 * ============================================================ */
typedef struct {
    /* TLS/SSL */
    bool       tls_detected;
    TLSSession tls;

    /* HTTP */
    bool         http_detected;
    HTTPRequest  http_req;
    HTTPResponse http_resp;
    bool         http_req_seen;
    bool         http_resp_seen;

    /* DNS */
    bool      dns_detected;
    ParsedDNS dns_query;
    ParsedDNS dns_response;
    bool      dns_query_seen;
    bool      dns_resp_seen;
    int       dns_trans_logged;   /* Number of DNS transactions already logged inline */
} AppState;

/* ============================================================
 * Connection Record  — one per flow
 * ============================================================ */
typedef struct ConnRecord {
    ConnKey   key;
    ConnState state;

    /* Timestamps (Unix seconds.microseconds) */
    double   ts_start;
    double   ts_last;
    double   duration;

    /* Traffic counters */
    ConnDir  orig;           /* initiator -> responder */
    ConnDir  resp;           /* responder -> initiator */

    /* Zeek conn.log identity fields */
    char     uid[UID_LENGTH];
    char     src_ip_str[INET_ADDRSTRLEN];
    char     dst_ip_str[INET_ADDRSTRLEN];
    char     service[32];    /* Guessed service name (e.g. "http") */

    /* Application layer */
    AppState app;

    /* Internal bookkeeping */
    bool     logged;             /* Has conn.log entry been written? */
    struct ConnRecord *next;     /* Hash chain */
} ConnRecord;

/* ============================================================
 * Connection Table
 * ============================================================ */
typedef struct {
    ConnRecord *buckets[CONN_TABLE_SIZE];
    int         count;           /* Currently active connections */
    int         total;           /* Total connections seen (ever) */
    int         tcp_timeout;     /* Inactivity timeout (seconds) */
    int         udp_timeout;
    int         icmp_timeout;
} ConnTable;

/* ============================================================
 * Callback type used by expiry/flush functions
 * ============================================================ */
typedef void (*ConnExpireCallback)(ConnRecord *rec, void *userdata);

/* ============================================================
 * Public API
 * ============================================================ */

/* Get current wall-clock time as double (seconds.microseconds) */
double get_timestamp(void);

/* Initialize table with per-protocol inactivity timeouts */
void conn_table_init(ConnTable *ct,
                     int tcp_timeout,
                     int udp_timeout,
                     int icmp_timeout);

/* Free all records (no callbacks fired) */
void conn_table_destroy(ConnTable *ct);

/* Update (or create) a flow record from a parsed packet.
 * Returns the record, or NULL on allocation failure. */
ConnRecord *conn_table_update(ConnTable *ct,
                              const ParsedPacket *pkt,
                              double ts);

/* Look up a flow without creating it. Returns NULL if not found. */
ConnRecord *conn_table_lookup(ConnTable *ct, const ConnKey *key);

/* Sweep expired flows. Fires callback for each before freeing.
 * Returns number of flows expired. */
int conn_table_expire(ConnTable *ct,
                      double now,
                      ConnExpireCallback cb,
                      void *userdata);

/* Flush all remaining flows (called at shutdown). */
void conn_table_flush(ConnTable *ct,
                      ConnExpireCallback cb,
                      void *userdata);

/* Return a Zeek-compatible conn_state string for this record */
const char *conn_state_str(const ConnRecord *rec);

#endif /* ZEEK_CONN_TRACKER_H */

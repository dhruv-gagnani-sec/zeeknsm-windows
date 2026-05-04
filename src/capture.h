/*
 * capture.h - Windows Raw Socket Packet Capture
 *
 * Uses a SOCK_RAW / IPPROTO_IP socket with SIO_RCVALL to receive
 * all inbound AND outbound IP datagrams on a single local interface.
 *
 * Requirements:
 *   - Must be run as Administrator (SIO_RCVALL needs SeDebugPrivilege)
 *   - Winsock 2.2
 *   - Links against ws2_32.lib and iphlpapi.lib
 */

#ifndef ZEEK_CAPTURE_H
#define ZEEK_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#define CAPTURE_SNAP_MAX   65535   /* Maximum bytes per packet */
#define CAPTURE_TIMEOUT_MS 500     /* recv() timeout — lets the loop check running */

/* ============================================================
 * Capture Handle
 * ============================================================ */
typedef struct {
    SOCKET   raw_sock;
    char     bound_ip[INET_ADDRSTRLEN];   /* Actual IP we are bound to */
    int      snaplen;

    /* Statistics (updated by capture_recv) */
    uint64_t pkts_recv;
    uint64_t pkts_drop;
    uint64_t bytes_recv;

    /* Set to false to stop the capture loop gracefully */
    volatile bool running;
} CaptureHandle;

/* ============================================================
 * Public API
 * ============================================================ */

/* Open a raw capture socket bound to the given local IP.
 * Pass "auto" to have the function select the first non-loopback
 * interface automatically.
 * snaplen: maximum bytes per packet (0 → CAPTURE_SNAP_MAX).
 * Returns 0 on success, -1 on failure. */
int capture_open(CaptureHandle *cap, const char *ip, int snaplen);

/* Receive one raw IP packet into buf.
 * Returns: > 0 bytes received,  0 on timeout,  -1 on hard error. */
int capture_recv(CaptureHandle *cap, uint8_t *buf, int buf_len);

/* Signal the capture loop to stop (sets cap->running = false). */
void capture_stop(CaptureHandle *cap);

/* Close socket and free resources (idempotent). */
void capture_close(CaptureHandle *cap);

/* Enumerate adapters and write the first non-loopback IP into buf.
 * Returns 0 on success, -1 if no suitable adapter found. */
int capture_get_default_ip(char *buf, int buflen);

#endif /* ZEEK_CAPTURE_H */

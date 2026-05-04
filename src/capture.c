/*
 * capture.c - Windows Raw Socket Packet Capture Implementation
 *
 * Flow:
 *   capture_open()  → select / validate IP
 *                   → WSAStartup
 *                   → WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP)
 *                   → bind() to local IP:0
 *                   → WSAIoctl(SIO_RCVALL, RCVALL_ON)
 *                   → set recv timeout
 *
 *   capture_recv()  → recv() raw IP datagram
 *
 *   capture_close() → SIO_RCVALL off → closesocket → WSACleanup
 */

#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

/* ============================================================
 * capture_get_default_ip
 * Walk the adapter list (GetAdaptersInfo) and return the first
 * non-loopback, non-zero IPv4 address.
 * ============================================================ */
int capture_get_default_ip(char *buf, int buflen) {
    ULONG sz = 0;
    /* First call with NULL to get required buffer size */
    GetAdaptersInfo(NULL, &sz);
    if (sz == 0) {
        fprintf(stderr, "[capture] GetAdaptersInfo size query failed\n");
        return -1;
    }

    IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)malloc(sz);
    if (!info) return -1;

    DWORD ret = GetAdaptersInfo(info, &sz);
    if (ret != ERROR_SUCCESS) {
        fprintf(stderr, "[capture] GetAdaptersInfo failed: %lu\n", ret);
        free(info);
        return -1;
    }

    int found = -1;
    for (IP_ADAPTER_INFO *a = info; a; a = a->Next) {
        const char *ip = a->IpAddressList.IpAddress.String;
        /* Skip null, loopback, and APIPA addresses */
        if (!ip || ip[0] == '\0')          continue;
        if (strcmp(ip, "0.0.0.0")   == 0)  continue;
        if (strcmp(ip, "127.0.0.1") == 0)  continue;
        if (strncmp(ip, "169.254.", 8) == 0) continue;

        strncpy(buf, ip, (size_t)(buflen - 1));
        buf[buflen - 1] = '\0';
        found = 0;
        break;
    }

    free(info);

    if (found != 0)
        fprintf(stderr, "[capture] No suitable network interface found\n");
    return found;
}

/* ============================================================
 * capture_open
 * ============================================================ */
int capture_open(CaptureHandle *cap, const char *ip, int snaplen) {
    memset(cap, 0, sizeof(CaptureHandle));
    cap->snaplen = (snaplen > 0 && snaplen <= CAPTURE_SNAP_MAX)
                   ? snaplen : CAPTURE_SNAP_MAX;
    cap->running     = true;
    cap->raw_sock    = INVALID_SOCKET;

    /* ---- Resolve bind IP ---- */
    if (!ip || strcmp(ip, "auto") == 0) {
        if (capture_get_default_ip(cap->bound_ip,
                                   sizeof(cap->bound_ip)) != 0) {
            fprintf(stderr, "[capture] Cannot determine default interface IP\n");
            return -1;
        }
    } else {
        strncpy(cap->bound_ip, ip, sizeof(cap->bound_ip) - 1);
    }
    fprintf(stdout, "[capture] Interface IP: %s\n", cap->bound_ip);

    /* ---- Initialise Winsock ---- */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[capture] WSAStartup failed: %d\n",
                WSAGetLastError());
        return -1;
    }

    /* ---- Create raw IP socket ---- */
    cap->raw_sock = WSASocketW(AF_INET, SOCK_RAW, IPPROTO_IP,
                               NULL, 0, WSA_FLAG_OVERLAPPED);
    if (cap->raw_sock == INVALID_SOCKET) {
        fprintf(stderr,
                "[capture] WSASocket(SOCK_RAW) failed: %d  "
                "— ensure you are running as Administrator\n",
                WSAGetLastError());
        WSACleanup();
        return -1;
    }

    /* ---- Option: include IP header in received data ---- */
    DWORD hdr_incl = 1;
    setsockopt(cap->raw_sock, IPPROTO_IP, IP_HDRINCL,
               (const char *)&hdr_incl, sizeof(hdr_incl));

    /* ---- Bind to the local IP (port 0) ---- */
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(cap->bound_ip);
    sa.sin_port        = 0;

    if (bind(cap->raw_sock, (struct sockaddr *)&sa, sizeof(sa))
            == SOCKET_ERROR) {
        fprintf(stderr, "[capture] bind() failed: %d\n", WSAGetLastError());
        closesocket(cap->raw_sock);
        WSACleanup();
        return -1;
    }

    /* ---- Enable SIO_RCVALL — receive ALL IP packets from this interface ---- */
    DWORD in_val  = RCVALL_ON;
    DWORD out_val = 0;
    DWORD bytes   = 0;
    if (WSAIoctl(cap->raw_sock, SIO_RCVALL,
                 &in_val,  sizeof(in_val),
                 &out_val, sizeof(out_val),
                 &bytes, NULL, NULL) == SOCKET_ERROR) {
        fprintf(stderr, "[capture] SIO_RCVALL failed: %d\n",
                WSAGetLastError());
        closesocket(cap->raw_sock);
        WSACleanup();
        return -1;
    }

    /* ---- Set recv timeout so the loop can check cap->running ---- */
    DWORD tv_ms = CAPTURE_TIMEOUT_MS;
    setsockopt(cap->raw_sock, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&tv_ms, sizeof(tv_ms));

    fprintf(stdout, "[capture] Raw socket ready (snaplen=%d)\n",
            cap->snaplen);
    return 0;
}

/* ============================================================
 * capture_recv
 * Returns > 0  : bytes received (packet in buf)
 *          0   : timeout / would-block (caller should check running)
 *         -1   : hard error
 * ============================================================ */
int capture_recv(CaptureHandle *cap, uint8_t *buf, int buf_len) {
    if (!cap->running || cap->raw_sock == INVALID_SOCKET) return -1;

    int n = recv(cap->raw_sock, (char *)buf, buf_len, 0);
    if (n > 0) {
        cap->pkts_recv++;
        cap->bytes_recv += (uint64_t)n;
        return n;
    }

    int err = WSAGetLastError();
    if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK || err == WSAEINTR)
        return 0;   /* Timeout — caller should loop and check running */

    if (cap->running) {
        /* Don't spam errors if we are shutting down */
        cap->pkts_drop++;
    }
    return 0;   /* Non-fatal: keep looping */
}

/* ============================================================
 * capture_stop
 * ============================================================ */
void capture_stop(CaptureHandle *cap) {
    cap->running = false;
}

/* ============================================================
 * capture_close
 * ============================================================ */
void capture_close(CaptureHandle *cap) {
    cap->running = false;

    if (cap->raw_sock != INVALID_SOCKET) {
        /* Disable promiscuous mode before closing */
        DWORD in_val  = RCVALL_OFF;
        DWORD out_val = 0;
        DWORD bytes   = 0;
        WSAIoctl(cap->raw_sock, SIO_RCVALL,
                 &in_val,  sizeof(in_val),
                 &out_val, sizeof(out_val),
                 &bytes, NULL, NULL);

        closesocket(cap->raw_sock);
        cap->raw_sock = INVALID_SOCKET;
    }

    WSACleanup();

    fprintf(stdout,
            "[capture] Closed — pkts_recv=%llu  pkts_drop=%llu  bytes=%llu\n",
            (unsigned long long)cap->pkts_recv,
            (unsigned long long)cap->pkts_drop,
            (unsigned long long)cap->bytes_recv);
}

/*
 * main.c - ZeekNSM for Windows — Entry Point & Main Monitoring Loop
 *
 * Pipeline:
 *
 *   CaptureHandle               (capture.c)  raw IP datagrams
 *        ↓
 *   parse_packet()              (protocols.c) IPv4/TCP/UDP/ICMP
 *        ↓
 *   conn_table_update()         (conn_tracker.c) 5-tuple flow state
 *        ↓
 *   classify_application()      (this file)  TLS / HTTP / DNS dispatch
 *        ↓
 *   event_engine_analyze()      (event_engine.c) real-time detection
 *        ↓ (on flow expiry)
 *   event_engine_on_close()     application-layer log records
 *   logger_write_conn()         conn.log
 *
 *
 * Usage:
 *   zeek-nsm.exe [--config <path>]           Run in console (default)
 *   zeek-nsm.exe --install [--config <path>] Install Windows service
 *   zeek-nsm.exe --uninstall                 Remove Windows service
 *   zeek-nsm.exe --print-config              Show loaded config
 *   zeek-nsm.exe --version                   Print version
 *   zeek-nsm.exe --help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "config.h"
#include "protocols.h"
#include "capture.h"
#include "conn_tracker.h"
#include "event_engine.h"
#include "logger.h"
#include "service.h"
#include "uid.h"

/* TLS / HTTP / DNS parsers — needed for classify_application() */
#include "tls_parser.h"
#include "http_parser.h"
#include "dns_parser.h"

#define ZEEK_NSM_VERSION   "2.0.0"
#define DEFAULT_CONFIG     "C:\\zeek\\zeek.conf"

/* How often to run the expiry sweep (seconds) */
#define EXPIRE_INTERVAL    5.0

/* ============================================================
 * Global stop flag — set by CTRL+C / console handler
 * (Also used by service.c via zeek_main_loop parameter)
 * ============================================================ */
static volatile bool g_console_stop = false;

static BOOL WINAPI console_handler(DWORD ctrl) {
    switch (ctrl) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_console_stop = true;
        fprintf(stdout, "\n[main] Interrupt received — shutting down...\n");
        return TRUE;
    }
    return FALSE;
}

/* ============================================================
 * Expiry callback context
 * ============================================================ */
typedef struct {
    Logger      *log;
    EventEngine *eng;
    double       ts;
} ExpireCtx;

static void on_conn_expire(ConnRecord *rec, void *userdata) {
    ExpireCtx *ctx = (ExpireCtx *)userdata;
    /* Write app-layer records and final checks */
    event_engine_on_close(ctx->eng, rec, ctx->log, ctx->ts);
    /* Write conn.log entry */
    logger_write_conn(ctx->log, rec);
}

/* ============================================================
 * Application-Layer Classifier
 *
 * Called once per packet for the connection it belongs to.
 * Routes the payload to the appropriate parser and stores
 * parsed state in conn->app.
 *
 * is_orig: true if this packet is from the initiator → responder.
 * ============================================================ */
static void classify_application(ConnRecord         *conn,
                                  const ParsedPacket *pkt,
                                  bool                is_orig,
                                  Logger             *log) {
    const uint8_t *payload     = pkt->payload;
    int            payload_len = pkt->payload_len;

    if (!payload || payload_len <= 0) return;

    AppState *app = &conn->app;

    uint16_t dport = conn->key.dst_port;
    uint16_t sport = conn->key.src_port;

    /* ----------------------------------------------------------
     * DNS  (port 53, 853/DoT, 5353/mDNS, 5355/LLMNR)
     *
     * DNS is transaction-based (query → response).  We must NOT
     * gate on `dns_detected` because that blocks the response
     * packet from ever being parsed.  Instead we parse every
     * matching packet, log completed transactions immediately,
     * and reset the per-flow state for the next transaction.
     * ---------------------------------------------------------- */
    bool is_dns_port = (dport == 53   || sport == 53   ||
                        dport == 5353 || sport == 5353 ||
                        dport == 5355 || sport == 5355 ||
                        dport == 853  || sport == 853);

    if (is_dns_port) {
        /* For TCP port 853 (DoT), the DNS message may be prefixed
         * with a 2-byte length — skip it if present.             */
        const uint8_t *dns_data = payload;
        int            dns_len  = payload_len;
        if ((dport == 853 || sport == 853) &&
            conn->key.proto == PROTO_TCP && dns_len > 2) {
            uint16_t msg_len = (dns_data[0] << 8) | dns_data[1];
            if (msg_len <= dns_len - 2) {
                dns_data += 2;
                dns_len  -= 2;
            }
        }

        if (dns_is_likely(dns_data, dns_len)) {
            ParsedDNS dns;
            memset(&dns, 0, sizeof(dns));
            if (dns_parse(dns_data, dns_len, &dns)) {
                app->dns_detected = true;

                if (!dns.is_response) {
                    /* Incoming query — store it, overwriting any
                     * previous query that was already logged.     */
                    app->dns_query      = dns;
                    app->dns_query_seen = true;
                } else {
                    /* Incoming response — store it */
                    app->dns_response    = dns;
                    app->dns_resp_seen   = true;

                    /* We now have a response.  Log the transaction
                     * immediately so we never lose answers.       */
                    logger_write_dns(log, conn,
                        app->dns_query_seen ? &app->dns_query : NULL,
                        &app->dns_response);
                    app->dns_trans_logged++;

                    /* Reset for the next transaction on this flow */
                    app->dns_query_seen = false;
                    app->dns_resp_seen  = false;
                    memset(&app->dns_query,    0, sizeof(ParsedDNS));
                    memset(&app->dns_response, 0, sizeof(ParsedDNS));
                }
            }
        }
    }

    /* ----------------------------------------------------------
     * HTTP  (ports 80, 8080, 8888, 8000, 8081, 3000, 3128)
     * ---------------------------------------------------------- */
    if (dport == 80   || dport == 8080 || dport == 8888 ||
        dport == 8000 || dport == 8081 ||
        dport == 3000 || dport == 3128 ||
        sport == 80   || sport == 8080 || sport == 8081) {

        if (is_orig && !app->http_req_seen &&
            http_is_request(payload, payload_len)) {
            if (http_parse_request(payload, payload_len, &app->http_req)) {
                app->http_detected = true;
                app->http_req_seen = true;
            }
        } else if (!is_orig && !app->http_resp_seen &&
                   http_is_response(payload, payload_len)) {
            if (http_parse_response(payload, payload_len, &app->http_resp)) {
                app->http_detected  = true;
                app->http_resp_seen = true;
            }
        }
    }

    /* ----------------------------------------------------------
     * TLS/SSL  (ports 443, 8443, 465, 636, 993, 995, 5985, 5986,
     *           853/DoT, 5228/Android-GCM, 9443, 2083)
     *
     * Always attempt to parse both ClientHello and ServerHello
     * independently — they arrive on different directions and
     * carry different data (SNI+JA3 vs cipher+JA3S).
     * ---------------------------------------------------------- */
    if (dport == 443  || dport == 8443 || dport == 465  ||
        dport == 636  || dport == 993  || dport == 995  ||
        dport == 5985 || dport == 5986 || dport == 853  ||
        dport == 5228 || dport == 9443 || dport == 2083 ||
        sport == 443  || sport == 8443 || sport == 853) {

        if (tls_is_likely(payload, payload_len)) {
            app->tls_detected = true;
            int hs = tls_get_handshake_type(payload, payload_len);

            if (hs == TLS_HS_CLIENT_HELLO &&
                !app->tls.client_hello.is_valid) {
                tls_parse_client_hello(payload, payload_len,
                                       &app->tls.client_hello);
            }
            if (hs == TLS_HS_SERVER_HELLO &&
                !app->tls.server_hello.is_valid) {
                tls_parse_server_hello(payload, payload_len,
                                       &app->tls.server_hello);
                app->tls.established = true;
            }
        }
    }
}

/* ============================================================
 * zeek_main_loop
 *
 * The actual monitoring engine.  Declared in service.h so that
 * service.c can call it from ServiceMain().
 * ============================================================ */
int zeek_main_loop(const char *cfg_path, volatile bool *should_stop) {
    FILE *fdbg = fopen("C:\\zeek\\logs\\debug.log", "a");
    if (fdbg) { fprintf(fdbg, "[dbg] Starting zeek_main_loop\n"); fflush(fdbg); }

    /* ---- 1. Load Configuration ---- */
    ZeekConfig cfg;
    config_init_defaults(&cfg);

    const char *try_cfg = cfg_path;
    if (!try_cfg || strlen(try_cfg) == 0) try_cfg = "C:\\zeek\\zeek.conf";

    if (config_load(&cfg, try_cfg) != 0) {
        if (fdbg) { fprintf(fdbg, "[dbg] Config not found in [%s]. Trying C:\\zeek\\zeek.conf...\n", try_cfg); fflush(fdbg); }
        if (config_load(&cfg, "C:\\zeek\\zeek.conf") != 0) {
            if (fdbg) { fprintf(fdbg, "[dbg] No config found anywhere — using built-in defaults.\n"); fflush(fdbg); }
        } else {
             if (fdbg) { fprintf(fdbg, "[dbg] Loaded config from C:\\zeek\\zeek.conf\n"); fflush(fdbg); }
        }
    } else {
        if (fdbg) { fprintf(fdbg, "[dbg] Loaded config from [%s]\n", try_cfg); fflush(fdbg); }
    }
    
    if (fdbg) { fprintf(fdbg, "[dbg] Active Interface: %s. Log Dir: %s\n", cfg.interface_ip, cfg.log_dir); fflush(fdbg); }

    /* ---- 2. Subsystem Init ---- */
    uid_init();
    if (fdbg) { fprintf(fdbg, "[dbg] Opening capture...\n"); fflush(fdbg); }

    CaptureHandle cap;
    if (capture_open(&cap, cfg.interface_ip, cfg.snaplen) != 0) {
        if (fdbg) { fprintf(fdbg, "[dbg] Fatal: packet capture failed.\n"); fclose(fdbg); }
        return -1;
    }

    if (fdbg) { fprintf(fdbg, "[dbg] Capture opened on %s. Init conn_tracker...\n", cap.bound_ip); fflush(fdbg); }

    ConnTable *ct = calloc(1, sizeof(ConnTable));
    Logger *log = calloc(1, sizeof(Logger));
    EventEngine *eng = calloc(1, sizeof(EventEngine));

    if (!ct || !log || !eng) {
        if (fdbg) { fprintf(fdbg, "[dbg] Fatal: Memory allocation failed.\n"); fclose(fdbg); }
        capture_close(&cap);
        return -1;
    }

    conn_table_init(ct,
                    cfg.tcp_inactivity_timeout,
                    cfg.udp_inactivity_timeout,
                    cfg.icmp_inactivity_timeout);

    if (fdbg) { fprintf(fdbg, "[dbg] Init logger...\n"); fflush(fdbg); }
    if (logger_init(log,
                    cfg.log_dir,
                    cfg.rotation_interval,
                    cfg.max_file_size,
                    cfg.enable_conn,
                    cfg.enable_dns,
                    cfg.enable_http,
                    cfg.enable_ssl,
                    cfg.enable_notice,
                    cfg.enable_weird,
                    cfg.enable_stats) != 0) {
        if (fdbg) { fprintf(fdbg, "[dbg] Fatal: logger init failed.\n"); fclose(fdbg); }
        capture_close(&cap);
        free(ct); free(log); free(eng);
        return -1;
    }

    if (fdbg) { fprintf(fdbg, "[dbg] Init event engine...\n"); fflush(fdbg); }
    event_engine_init(eng, &cfg);

    /* ---- 3. Packet buffer & timing ---- */
    uint8_t pkt_buf[CAPTURE_SNAP_MAX];
    double  last_expire = get_timestamp();
    double  last_stats  = get_timestamp();
    int     stats_ivl   = cfg.stats_interval > 0 ? cfg.stats_interval : 30;

    fprintf(stdout,
            "[main] ZeekNSM v%s — monitoring started.\n"
            "       Logs : %s\n",
            ZEEK_NSM_VERSION, cfg.log_dir);

    /* ---- 4. Main Capture Loop ---- */
    while (!(*should_stop) && !g_console_stop && cap.running) {
        int pkt_len = capture_recv(&cap, pkt_buf, sizeof(pkt_buf));
        double now  = get_timestamp();

        if (pkt_len > 0) {
            /* Parse raw IP */
            ParsedPacket pkt;
            if (parse_packet(pkt_buf, pkt_len, &pkt) && pkt.is_valid &&
                !pkt.is_fragment) {

                /* Update flow table */
                ConnRecord *conn = conn_table_update(ct, &pkt, now);
                if (conn) {
                    /* Determine direction: is this packet from the
                     * flow originator (first seen side)? */
                    bool is_orig = (pkt.ip->src_addr == conn->key.src_ip);

                    /* Attempt application-layer classification */
                    classify_application(conn, &pkt, is_orig, log);

                    /* Run detection checks on early packets only
                     * to avoid redundant work per-packet */
                    uint64_t total_pkts = conn->orig.pkts + conn->resp.pkts;
                    if (total_pkts <= 5)
                        event_engine_analyze(eng, conn, log, now);
                }
            }
        }

        /* ---- 5. Periodic: expire flows ---- */
        if ((now - last_expire) >= EXPIRE_INTERVAL) {
            last_expire = now;
            ExpireCtx ctx = { log, eng, now };
            int n = conn_table_expire(ct, now, on_conn_expire, &ctx);
            (void)n;   /* Could log n if desired */

            /* Rotate logs if scheduled */
            logger_rotate_if_needed(log, now);
        }

        /* ---- 6. Periodic: write stats ---- */
        if ((now - last_stats) >= (double)stats_ivl) {
            last_stats = now;
            logger_write_stats(log, now, ct->count,
                               cap.pkts_recv, cap.pkts_drop,
                               cap.bytes_recv);
        }
    }

    /* ---- 7. Shutdown: flush remaining flows ---- */
    fprintf(stdout, "[main] Flushing %d active flows...\n", ct->count);
    double shutdown_ts = get_timestamp();
    ExpireCtx ctx_down = { log, eng, shutdown_ts };
    conn_table_flush(ct, on_conn_expire, &ctx_down);

    /* Final stats record */
    logger_write_stats(log, shutdown_ts, 0,
                       cap.pkts_recv, cap.pkts_drop, cap.bytes_recv);

    fprintf(stdout,
            "[main] Shutdown complete.\n"
            "       %-20s %llu\n"
            "       %-20s %llu\n"
            "       %-20s %llu\n"
            "       %-20s %d\n"
            "       %-20s %llu\n"
            "       %-20s %llu\n",
            "Packets received:", (unsigned long long)cap.pkts_recv,
            "Packets dropped:",  (unsigned long long)cap.pkts_drop,
            "Bytes received:",   (unsigned long long)cap.bytes_recv,
            "Total flows:",      ct->total,
            "Notices raised:",   (unsigned long long)eng->notices_generated,
            "Weirds raised:",    (unsigned long long)eng->weirds_generated);

    /* ---- 8. Cleanup ---- */
    conn_table_destroy(ct);
    logger_close(log);
    capture_close(&cap);
    
    free(ct);
    free(log);
    free(eng);
    return 0;
}

/* ============================================================
 * main() — CLI argument dispatch
 * ============================================================ */
int main(int argc, char *argv[]) {
    const char *cfg_path      = DEFAULT_CONFIG;
    bool        install_svc   = false;
    bool        uninstall_svc = false;
    bool        run_as_svc    = false;
    bool        print_cfg     = false;

    /* Parse CLI */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            cfg_path = argv[++i];
        } else if (strcmp(argv[i], "--install") == 0) {
            install_svc = true;
        } else if (strcmp(argv[i], "--uninstall") == 0) {
            uninstall_svc = true;
        } else if (strcmp(argv[i], "--service") == 0) {
            run_as_svc = true;
        } else if (strcmp(argv[i], "--print-config") == 0) {
            print_cfg = true;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("ZeekNSM version %s\n", ZEEK_NSM_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            printf(
                "ZeekNSM v%s — Zeek-based Network Security Monitor for Windows\n\n"
                "Usage: zeek-nsm.exe [options]\n\n"
                "  --config <path>    Path to zeek.conf  (default: %s)\n"
                "  --install          Install as Windows auto-start service\n"
                "  --uninstall        Remove Windows service\n"
                "  --service          Run under Service Control Manager\n"
                "  --print-config     Print resolved configuration and exit\n"
                "  --version          Print version and exit\n"
                "  --help             This message\n\n"
                "Examples:\n"
                "  zeek-nsm.exe                                 # Console mode\n"
                "  zeek-nsm.exe --config C:\\zeek\\zeek.conf      # Custom config\n"
                "  zeek-nsm.exe --install --config C:\\zeek\\zeek.conf\n"
                "  zeek-nsm.exe --uninstall\n",
                ZEEK_NSM_VERSION, DEFAULT_CONFIG
            );
            return 0;
        }
    }

    if (print_cfg) {
        ZeekConfig cfg;
        config_init_defaults(&cfg);
        config_load(&cfg, cfg_path);
        config_print(&cfg);
        return 0;
    }

    if (install_svc) {
        char exe[MAX_PATH];
        GetModuleFileNameA(NULL, exe, MAX_PATH);
        return service_install(exe, cfg_path);
    }

    if (uninstall_svc) {
        return service_uninstall();
    }

    /* Install CTRL+C handler for console mode */
    SetConsoleCtrlHandler(console_handler, TRUE);

    /* Dispatch to service dispatcher or run directly */
    return service_run(cfg_path, run_as_svc);
}

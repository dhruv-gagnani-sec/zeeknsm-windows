/*
 * service.h - Windows Service Wrapper
 *
 * Registers ZeekNSM as a Windows Service so it starts automatically
 * at boot under the LOCAL_SYSTEM account (or a dedicated low-priv
 * account if you re-configure it).
 *
 * Usage (run as Administrator):
 *   zeek-nsm.exe --install [--config <path>]   Install & enable
 *   zeek-nsm.exe --uninstall                   Remove service
 *   zeek-nsm.exe --service  [--config <path>]  Called by SCM internally
 *   zeek-nsm.exe [--config <path>]             Run in console mode
 */

#ifndef ZEEK_SERVICE_H
#define ZEEK_SERVICE_H

#include <windows.h>
#include <stdbool.h>

/* Service identity */
#define SERVICE_NAME        "ZeekNSM"
#define SERVICE_DISPLAY     "Zeek NSM — Network Security Monitor"
#define SERVICE_DESCRIPTION \
    "Zeek-based packet capture and protocol analysis. " \
    "Produces Wazuh-compatible JSON logs: " \
    "conn.log, dns.log, http.log, ssl.log, notice.log, weird.log, stats.log."

/* ============================================================
 * Public API
 * ============================================================ */

/* Install as an auto-start Windows service.
 * exe_path : full path to the zeek-nsm.exe binary
 * cfg_path : path to zeek.conf (embedded in the service binary path)
 * Returns 0 on success. */
int service_install(const char *exe_path, const char *cfg_path);

/* Remove the service (stops it first if running). Returns 0 on success. */
int service_uninstall(void);

/* Start the service control dispatcher (if run_as_service is true) or
 * run the main loop directly in the calling process. */
int service_run(const char *cfg_path, bool run_as_service);

/* ============================================================
 * Main monitoring loop — implemented in main.c
 * Exposed here so service_main() can call it.
 * should_stop is set to true by the SCM STOP control or CTRL+C.
 * ============================================================ */
int zeek_main_loop(const char *cfg_path, volatile bool *should_stop);

#endif /* ZEEK_SERVICE_H */

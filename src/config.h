/*
 * config.h - Configuration File Parser
 * Reads INI-style configuration for Zeek NSM
 */

#ifndef ZEEK_CONFIG_H
#define ZEEK_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_PATH_LEN 512
#define MAX_IFACE_LEN 256

typedef struct {
    /* [capture] */
    char interface_ip[MAX_IFACE_LEN]; /* "auto" or specific IP */
    bool promiscuous;
    int snaplen;
    int buffer_size;

    /* [logging] */
    char log_dir[MAX_PATH_LEN];
    int rotation_interval;    /* seconds */
    int64_t max_file_size;    /* bytes */
    bool enable_conn;
    bool enable_dns;
    bool enable_http;
    bool enable_ssl;
    bool enable_notice;
    bool enable_weird;
    bool enable_stats;
    int stats_interval;       /* seconds between stats log entries */

    /* [detection] */
    int port_scan_threshold;
    int port_scan_window;     /* seconds */
    int dns_tunnel_query_len;

    /* [connection] */
    int tcp_inactivity_timeout;
    int udp_inactivity_timeout;
    int icmp_inactivity_timeout;

    /* [service] */
    bool auto_start;
} ZeekConfig;

/* Initialize config with defaults */
void config_init_defaults(ZeekConfig *cfg);

/* Load config from file; returns 0 on success, -1 on error */
int config_load(ZeekConfig *cfg, const char *filepath);

/* Print current configuration to stdout */
void config_print(const ZeekConfig *cfg);

/* Global config instance */
extern ZeekConfig g_config;

#endif /* ZEEK_CONFIG_H */

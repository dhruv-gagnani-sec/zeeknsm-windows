/*
 * config.c - Configuration File Parser
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

ZeekConfig g_config;

 

static bool parse_bool(const char *val) {
    return (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 || 
            strcmp(val, "1") == 0 || strcmp(val, "on") == 0);
}

void config_init_defaults(ZeekConfig *cfg) {
    memset(cfg, 0, sizeof(ZeekConfig));

    /* [capture] */
    strncpy(cfg->interface_ip, "auto", MAX_IFACE_LEN - 1);
    cfg->promiscuous = true;
    cfg->snaplen = 65535;
    cfg->buffer_size = 4 * 1024 * 1024;  /* 4MB */

    /* [logging] */
    strncpy(cfg->log_dir, "C:\\zeek\\logs", MAX_PATH_LEN - 1);
    cfg->rotation_interval = 86400;       /* 24 hours */
    cfg->max_file_size = 100 * 1024 * 1024; /* 100MB */
    cfg->enable_conn = true;
    cfg->enable_dns = true;
    cfg->enable_http = true;
    cfg->enable_ssl = true;
    cfg->enable_notice = true;
    cfg->enable_weird = true;
    cfg->enable_stats = true;
    cfg->stats_interval = 30;

    /* [detection] */
    cfg->port_scan_threshold = 15;
    cfg->port_scan_window = 60;
    cfg->dns_tunnel_query_len = 100;

    /* [connection] */
    cfg->tcp_inactivity_timeout = 300;
    cfg->udp_inactivity_timeout = 60;
    cfg->icmp_inactivity_timeout = 30;

    /* [service] */
    cfg->auto_start = true;
}

int config_load(ZeekConfig *cfg, const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "[config] Cannot open config file: %s\n", filepath);
        return -1;
    }

    char line[1024];
    char section[64] = "";

    while (fgets(line, sizeof(line), f)) {
        /* Remove comments and newlines */
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        comment = strchr(line, ';');
        if (comment) *comment = '\0';
        
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        
        size_t len = strlen(p);
        if (len == 0) continue;
        
        /* Remove trailing whitespace */
        while (len > 0 && isspace((unsigned char)p[len - 1])) {
            p[--len] = '\0';
        }
        if (len == 0) continue;

        /* Section header */
        if (p[0] == '[') {
            char *end = strchr(p, ']');
            if (end) {
                *end = '\0';
                strncpy(section, p + 1, sizeof(section) - 1);
                section[sizeof(section) - 1] = '\0';
            }
            continue;
        }

        /* Key = Value */
        char *eq = strchr(p, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = p;
        char *val = eq + 1;
        
        /* Trim key and value */
        while (isspace((unsigned char)*key)) key++;
        char *key_end = key + strlen(key) - 1;
        while (key_end > key && isspace((unsigned char)*key_end)) *key_end-- = '\0';
        
        while (isspace((unsigned char)*val)) val++;
        char *val_end = val + strlen(val) - 1;
        while (val_end > val && isspace((unsigned char)*val_end)) *val_end-- = '\0';

        /* [capture] section */
        if (strcmp(section, "capture") == 0) {
            if (strcmp(key, "interface") == 0) {
                strncpy(cfg->interface_ip, val, MAX_IFACE_LEN - 1);
            } else if (strcmp(key, "promiscuous") == 0) {
                cfg->promiscuous = parse_bool(val);
            } else if (strcmp(key, "snaplen") == 0) {
                cfg->snaplen = atoi(val);
            } else if (strcmp(key, "buffer_size") == 0) {
                cfg->buffer_size = atoi(val);
            }
        }
        /* [logging] section */
        else if (strcmp(section, "logging") == 0) {
            if (strcmp(key, "log_dir") == 0) {
                strncpy(cfg->log_dir, val, MAX_PATH_LEN - 1);
            } else if (strcmp(key, "rotation_interval") == 0) {
                cfg->rotation_interval = atoi(val);
            } else if (strcmp(key, "max_file_size") == 0) {
                cfg->max_file_size = _atoi64(val);
            } else if (strcmp(key, "enable_conn") == 0) {
                cfg->enable_conn = parse_bool(val);
            } else if (strcmp(key, "enable_dns") == 0) {
                cfg->enable_dns = parse_bool(val);
            } else if (strcmp(key, "enable_http") == 0) {
                cfg->enable_http = parse_bool(val);
            } else if (strcmp(key, "enable_ssl") == 0) {
                cfg->enable_ssl = parse_bool(val);
            } else if (strcmp(key, "enable_notice") == 0) {
                cfg->enable_notice = parse_bool(val);
            } else if (strcmp(key, "enable_weird") == 0) {
                cfg->enable_weird = parse_bool(val);
            } else if (strcmp(key, "enable_stats") == 0) {
                cfg->enable_stats = parse_bool(val);
            } else if (strcmp(key, "stats_interval") == 0) {
                cfg->stats_interval = atoi(val);
            }
        }
        /* [detection] section */
        else if (strcmp(section, "detection") == 0) {
            if (strcmp(key, "port_scan_threshold") == 0) {
                cfg->port_scan_threshold = atoi(val);
            } else if (strcmp(key, "port_scan_window") == 0) {
                cfg->port_scan_window = atoi(val);
            } else if (strcmp(key, "dns_tunnel_query_len") == 0) {
                cfg->dns_tunnel_query_len = atoi(val);
            }
        }
        /* [connection] section */
        else if (strcmp(section, "connection") == 0) {
            if (strcmp(key, "tcp_inactivity_timeout") == 0) {
                cfg->tcp_inactivity_timeout = atoi(val);
            } else if (strcmp(key, "udp_inactivity_timeout") == 0) {
                cfg->udp_inactivity_timeout = atoi(val);
            } else if (strcmp(key, "icmp_inactivity_timeout") == 0) {
                cfg->icmp_inactivity_timeout = atoi(val);
            }
        }
        /* [service] section */
        else if (strcmp(section, "service") == 0) {
            if (strcmp(key, "auto_start") == 0) {
                cfg->auto_start = parse_bool(val);
            }
        }
    }

    fclose(f);
    return 0;
}

void config_print(const ZeekConfig *cfg) {
    printf("=== Zeek NSM Configuration ===\n");
    printf("[capture]\n");
    printf("  interface      = %s\n", cfg->interface_ip);
    printf("  promiscuous    = %s\n", cfg->promiscuous ? "yes" : "no");
    printf("  snaplen        = %d\n", cfg->snaplen);
    printf("  buffer_size    = %d\n", cfg->buffer_size);
    printf("[logging]\n");
    printf("  log_dir        = %s\n", cfg->log_dir);
    printf("  rotation_int   = %d\n", cfg->rotation_interval);
    printf("  max_file_size  = %lld\n", (long long)cfg->max_file_size);
    printf("  conn=%s dns=%s http=%s ssl=%s notice=%s weird=%s stats=%s\n",
        cfg->enable_conn ? "on" : "off",
        cfg->enable_dns ? "on" : "off",
        cfg->enable_http ? "on" : "off",
        cfg->enable_ssl ? "on" : "off",
        cfg->enable_notice ? "on" : "off",
        cfg->enable_weird ? "on" : "off",
        cfg->enable_stats ? "on" : "off");
    printf("[detection]\n");
    printf("  port_scan      = %d ports in %ds\n", cfg->port_scan_threshold, cfg->port_scan_window);
    printf("  dns_tunnel_len = %d\n", cfg->dns_tunnel_query_len);
    printf("[connection]\n");
    printf("  tcp_timeout    = %ds\n", cfg->tcp_inactivity_timeout);
    printf("  udp_timeout    = %ds\n", cfg->udp_inactivity_timeout);
    printf("  icmp_timeout   = %ds\n", cfg->icmp_inactivity_timeout);
    printf("==============================\n");
}

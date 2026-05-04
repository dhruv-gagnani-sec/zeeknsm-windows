/*
 * protocols.c - Network Protocol Parsing Implementation
 */

#include "protocols.h"
#include <stdio.h>
#include <string.h>

int parse_packet(const uint8_t *data, int len, ParsedPacket *pkt) {
    memset(pkt, 0, sizeof(ParsedPacket));
    pkt->raw_data = data;
    pkt->raw_len = len;

    /* Need at least an IP header */
    if (len < (int)sizeof(IPv4Header)) {
        return 0;
    }

    /* Parse IPv4 header */
    pkt->ip = (const IPv4Header *)data;

    if (IP_VERSION(pkt->ip) != 4) {
        return 0;  /* Only IPv4 supported */
    }

    pkt->ip_hdr_len = IP_HDR_LEN(pkt->ip);
    if (pkt->ip_hdr_len < 20 || pkt->ip_hdr_len > len) {
        return 0;
    }

    /* Convert IP addresses to strings */
    ip_to_str(pkt->ip->src_addr, pkt->src_ip_str, sizeof(pkt->src_ip_str));
    ip_to_str(pkt->ip->dst_addr, pkt->dst_ip_str, sizeof(pkt->dst_ip_str));

    /* Check for IP fragmentation */
    pkt->is_fragment = (IP_FRAGOFF(pkt->ip) != 0) || (IP_FLAGS(pkt->ip) & IP_FLAG_MF);

    pkt->proto = pkt->ip->protocol;
    const uint8_t *transport_data = data + pkt->ip_hdr_len;
    int transport_len = len - pkt->ip_hdr_len;

    switch (pkt->proto) {
    case PROTO_TCP:
        if (transport_len < (int)sizeof(TCPHeader)) {
            return 0;
        }
        pkt->transport.tcp = (const TCPHeader *)transport_data;
        pkt->src_port = ntohs(pkt->transport.tcp->src_port);
        pkt->dst_port = ntohs(pkt->transport.tcp->dst_port);
        
        {
            int tcp_hdr_len = TCP_HDR_LEN(pkt->transport.tcp);
            if (tcp_hdr_len < 20) tcp_hdr_len = 20;
            if (tcp_hdr_len <= transport_len) {
                pkt->payload = transport_data + tcp_hdr_len;
                pkt->payload_len = transport_len - tcp_hdr_len;
            } else {
                pkt->payload = NULL;
                pkt->payload_len = 0;
            }
        }
        break;

    case PROTO_UDP:
        if (transport_len < (int)sizeof(UDPHeader)) {
            return 0;
        }
        pkt->transport.udp = (const UDPHeader *)transport_data;
        pkt->src_port = ntohs(pkt->transport.udp->src_port);
        pkt->dst_port = ntohs(pkt->transport.udp->dst_port);
        pkt->payload = transport_data + sizeof(UDPHeader);
        pkt->payload_len = transport_len - sizeof(UDPHeader);
        break;

    case PROTO_ICMP:
        if (transport_len < (int)sizeof(ICMPHeader)) {
            return 0;
        }
        pkt->transport.icmp = (const ICMPHeader *)transport_data;
        pkt->src_port = 0;
        pkt->dst_port = 0;
        pkt->payload = transport_data + sizeof(ICMPHeader);
        pkt->payload_len = transport_len - sizeof(ICMPHeader);
        break;

    default:
        /* Unsupported protocol */
        pkt->payload = transport_data;
        pkt->payload_len = transport_len;
        break;
    }

    if (pkt->payload_len < 0) pkt->payload_len = 0;
    pkt->is_valid = 1;
    return 1;
}

void ip_to_str(uint32_t ip, char *buf, int buflen) {
    uint8_t *bytes = (uint8_t *)&ip;
    snprintf(buf, buflen, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

const char *proto_name(uint8_t proto) {
    switch (proto) {
    case PROTO_TCP:  return "tcp";
    case PROTO_UDP:  return "udp";
    case PROTO_ICMP: return "icmp";
    default:         return "unknown";
    }
}

void tcp_flags_str(uint8_t flags, char *buf, int buflen) {
    buf[0] = '\0';
    int pos = 0;
    
    if (flags & TCP_SYN) pos += snprintf(buf + pos, buflen - pos, "SYN,");
    if (flags & TCP_ACK) pos += snprintf(buf + pos, buflen - pos, "ACK,");
    if (flags & TCP_FIN) pos += snprintf(buf + pos, buflen - pos, "FIN,");
    if (flags & TCP_RST) pos += snprintf(buf + pos, buflen - pos, "RST,");
    if (flags & TCP_PSH) pos += snprintf(buf + pos, buflen - pos, "PSH,");
    if (flags & TCP_URG) pos += snprintf(buf + pos, buflen - pos, "URG,");
    if (flags & TCP_ECE) pos += snprintf(buf + pos, buflen - pos, "ECE,");
    if (flags & TCP_CWR) pos += snprintf(buf + pos, buflen - pos, "CWR,");
    
    /* Remove trailing comma */
    if (pos > 0 && buf[pos - 1] == ',') {
        buf[pos - 1] = '\0';
    }
}

const char *port_to_service(uint16_t port, uint8_t proto) {
    /* TCP services */
    if (proto == PROTO_TCP || proto == PROTO_UDP) {
        switch (port) {
        case 20:    return "ftp-data";
        case 21:    return "ftp";
        case 22:    return "ssh";
        case 23:    return "telnet";
        case 25:    return "smtp";
        case 53:    return "dns";
        case 67:    return "dhcp";
        case 68:    return "dhcp";
        case 80:    return "http";
        case 110:   return "pop3";
        case 123:   return "ntp";
        case 143:   return "imap";
        case 161:   return "snmp";
        case 162:   return "snmp-trap";
        case 389:   return "ldap";
        case 443:   return "ssl";
        case 445:   return "smb";
        case 465:   return "smtps";
        case 514:   return "syslog";
        case 587:   return "smtp";
        case 636:   return "ldaps";
        case 853:   return "dns-tls";
        case 993:   return "imaps";
        case 995:   return "pop3s";
        case 1433:  return "mssql";
        case 1434:  return "mssql";
        case 2083:  return "https-alt";
        case 3306:  return "mysql";
        case 3389:  return "rdp";
        case 5228:  return "android-gcm";
        case 5353:  return "mdns";
        case 5355:  return "llmnr";
        case 5432:  return "postgresql";
        case 5900:  return "vnc";
        case 5985:  return "winrm";
        case 5986:  return "winrm";
        case 6379:  return "redis";
        case 8000:  return "http-alt";
        case 8080:  return "http-alt";
        case 8081:  return "http-alt";
        case 8443:  return "https-alt";
        case 8888:  return "http-alt";
        case 9200:  return "elasticsearch";
        case 9443:  return "https-alt";
        case 27017: return "mongodb";
        default:    return NULL;
        }
    }
    return NULL;
}

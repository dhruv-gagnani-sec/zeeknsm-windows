/*
 * dns_parser.c - Deep DNS Protocol Parser Implementation
 */

#include "dns_parser.h"
#include <stdio.h>
#include <string.h>
#include <winsock2.h>

/* Parse a DNS domain name with compression support */
static int dns_parse_name(const uint8_t *pkt, int pkt_len, int offset,
                          char *name, int name_max, int *bytes_consumed) {
    int pos = offset;
    int out = 0;
    int jumps = 0;
    int first_jump = -1;
    bool jumped = false;

    if (pos >= pkt_len) return -1;

    while (pos < pkt_len) {
        uint8_t label_len = pkt[pos];

        /* Compression pointer */
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= pkt_len) return -1;
            if (!jumped) first_jump = pos + 2;
            jumped = true;
            pos = ((label_len & 0x3F) << 8) | pkt[pos + 1];
            if (++jumps > 32) return -1; /* Infinite loop protection */
            continue;
        }

        /* End of name */
        if (label_len == 0) {
            pos++;
            break;
        }

        /* Regular label */
        pos++;
        if (pos + label_len > pkt_len) return -1;
        if (out + label_len + 1 >= name_max) return -1;

        if (out > 0) {
            name[out++] = '.';
        }
        memcpy(name + out, pkt + pos, label_len);
        out += label_len;
        pos += label_len;
    }

    name[out] = '\0';
    
    if (bytes_consumed) {
        *bytes_consumed = jumped ? (first_jump - offset) : (pos - offset);
    }
    return 0;
}

/* Parse IPv4 address from rdata */
static void dns_parse_ipv4(const uint8_t *rdata, int rdlen, char *buf, int buflen) {
    if (rdlen >= 4) {
        snprintf(buf, buflen, "%u.%u.%u.%u", rdata[0], rdata[1], rdata[2], rdata[3]);
    } else {
        snprintf(buf, buflen, "(invalid)");
    }
}

/* Parse IPv6 address from rdata */
static void dns_parse_ipv6(const uint8_t *rdata, int rdlen, char *buf, int buflen) {
    if (rdlen >= 16) {
        snprintf(buf, buflen, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                rdata[0], rdata[1], rdata[2], rdata[3],
                rdata[4], rdata[5], rdata[6], rdata[7],
                rdata[8], rdata[9], rdata[10], rdata[11],
                rdata[12], rdata[13], rdata[14], rdata[15]);
    } else {
        snprintf(buf, buflen, "(invalid)");
    }
}

const char *dns_type_name(uint16_t type) {
    switch (type) {
    case DNS_TYPE_A:     return "A";
    case DNS_TYPE_NS:    return "NS";
    case DNS_TYPE_CNAME: return "CNAME";
    case DNS_TYPE_SOA:   return "SOA";
    case DNS_TYPE_PTR:   return "PTR";
    case DNS_TYPE_MX:    return "MX";
    case DNS_TYPE_TXT:   return "TXT";
    case DNS_TYPE_AAAA:  return "AAAA";
    case DNS_TYPE_SRV:   return "SRV";
    case DNS_TYPE_ANY:   return "ANY";
    default: {
        static char buf[16];
        snprintf(buf, sizeof(buf), "%u", type);
        return buf;
    }
    }
}

const char *dns_class_name(uint16_t cls) {
    switch (cls) {
    case 1:   return "C_INTERNET";
    case 3:   return "C_CHAOS";
    case 4:   return "C_HESIOD";
    case 255: return "C_ANY";
    default: {
        static char buf[16];
        snprintf(buf, sizeof(buf), "%u", cls);
        return buf;
    }
    }
}

const char *dns_rcode_name(int rcode) {
    switch (rcode) {
    case DNS_RCODE_NOERROR:  return "NOERROR";
    case DNS_RCODE_FORMERR:  return "FORMERR";
    case DNS_RCODE_SERVFAIL: return "SERVFAIL";
    case DNS_RCODE_NXDOMAIN: return "NXDOMAIN";
    case DNS_RCODE_NOTIMP:   return "NOTIMP";
    case DNS_RCODE_REFUSED:  return "REFUSED";
    default: {
        static char buf[16];
        snprintf(buf, sizeof(buf), "%d", rcode);
        return buf;
    }
    }
}

bool dns_is_likely(const uint8_t *data, int len) {
    if (len < 12) return false;  /* DNS header is 12 bytes */
    
    /* Basic sanity: question count should be >= 1, and counts shouldn't be absurd */
    uint16_t qd = ntohs(*(uint16_t *)(data + 4));
    uint16_t an = ntohs(*(uint16_t *)(data + 6));
    uint16_t ns = ntohs(*(uint16_t *)(data + 8));
    uint16_t ar = ntohs(*(uint16_t *)(data + 10));
    
    if (qd == 0 && an == 0) return false;
    if (qd > 10 || an > 100 || ns > 100 || ar > 100) return false;
    
    return true;
}

int dns_parse(const uint8_t *data, int len, ParsedDNS *dns) {
    memset(dns, 0, sizeof(ParsedDNS));

    if (len < 12) return 0;  /* Minimum DNS header size */

    /* Parse header */
    const DNSRawHeader *hdr = (const DNSRawHeader *)data;
    dns->trans_id = ntohs(hdr->id);
    uint16_t flags = ntohs(hdr->flags);
    
    dns->is_response = (flags & DNS_FLAG_QR) != 0;
    dns->opcode = (flags & DNS_FLAG_OPCODE) >> 11;
    dns->authoritative = (flags & DNS_FLAG_AA) != 0;
    dns->truncated = (flags & DNS_FLAG_TC) != 0;
    dns->recursion_desired = (flags & DNS_FLAG_RD) != 0;
    dns->recursion_available = (flags & DNS_FLAG_RA) != 0;
    dns->rcode = flags & DNS_FLAG_RCODE;

    uint16_t qd_count = ntohs(hdr->qd_count);
    uint16_t an_count = ntohs(hdr->an_count);

    int pos = 12;  /* After header */

    /* Parse question section */
    for (int i = 0; i < qd_count && i < 1; i++) {
        int consumed = 0;
        if (dns_parse_name(data, len, pos, dns->query, sizeof(dns->query), &consumed) < 0) {
            return 0;
        }
        pos += consumed;

        if (pos + 4 > len) return 0;
        dns->qtype = ntohs(*(uint16_t *)(data + pos));
        pos += 2;
        dns->qclass = ntohs(*(uint16_t *)(data + pos));
        pos += 2;
    }

    /* Skip remaining questions */
    for (int i = 1; i < qd_count; i++) {
        int consumed = 0;
        char skip_name[DNS_MAX_NAME_LEN];
        if (dns_parse_name(data, len, pos, skip_name, sizeof(skip_name), &consumed) < 0) break;
        pos += consumed + 4;
    }

    /* Parse answer section */
    dns->answer_count = 0;
    for (int i = 0; i < an_count && dns->answer_count < DNS_MAX_ANSWERS; i++) {
        DNSAnswer *ans = &dns->answers[dns->answer_count];
        int consumed = 0;

        if (dns_parse_name(data, len, pos, ans->name, sizeof(ans->name), &consumed) < 0) break;
        pos += consumed;

        if (pos + 10 > len) break;
        ans->type = ntohs(*(uint16_t *)(data + pos)); pos += 2;
        ans->cls  = ntohs(*(uint16_t *)(data + pos)); pos += 2;
        ans->ttl  = ntohl(*(uint32_t *)(data + pos)); pos += 4;
        uint16_t rdlen = ntohs(*(uint16_t *)(data + pos)); pos += 2;

        if (pos + rdlen > len) break;

        /* Parse rdata based on type */
        switch (ans->type) {
        case DNS_TYPE_A:
            dns_parse_ipv4(data + pos, rdlen, ans->rdata, sizeof(ans->rdata));
            break;
        case DNS_TYPE_AAAA:
            dns_parse_ipv6(data + pos, rdlen, ans->rdata, sizeof(ans->rdata));
            break;
        case DNS_TYPE_CNAME:
        case DNS_TYPE_NS:
        case DNS_TYPE_PTR:
            dns_parse_name(data, len, pos, ans->rdata, sizeof(ans->rdata), NULL);
            break;
        case DNS_TYPE_MX:
            if (rdlen >= 2) {
                /* Skip preference, parse name */
                dns_parse_name(data, len, pos + 2, ans->rdata, sizeof(ans->rdata), NULL);
            }
            break;
        case DNS_TYPE_TXT:
            if (rdlen > 1) {
                int txt_len = data[pos];
                if (txt_len > rdlen - 1) txt_len = rdlen - 1;
                if (txt_len >= (int)sizeof(ans->rdata)) txt_len = sizeof(ans->rdata) - 1;
                memcpy(ans->rdata, data + pos + 1, txt_len);
                ans->rdata[txt_len] = '\0';
            }
            break;
        default:
            snprintf(ans->rdata, sizeof(ans->rdata), "(type %u, %u bytes)", ans->type, rdlen);
            break;
        }

        pos += rdlen;
        dns->answer_count++;
    }

    /* Build Zeek-compatible computed fields */
    snprintf(dns->qtype_name, sizeof(dns->qtype_name), "%s", dns_type_name(dns->qtype));
    snprintf(dns->qclass_name, sizeof(dns->qclass_name), "%s", dns_class_name(dns->qclass));
    snprintf(dns->rcode_name, sizeof(dns->rcode_name), "%s", dns_rcode_name(dns->rcode));

    /* Build answers string (comma-separated) */
    dns->answers_str[0] = '\0';
    dns->ttls_str[0] = '\0';
    int ans_pos = 0, ttl_pos = 0;
    for (int i = 0; i < dns->answer_count; i++) {
        if (i > 0) {
            ans_pos += snprintf(dns->answers_str + ans_pos, sizeof(dns->answers_str) - ans_pos, ", ");
            ttl_pos += snprintf(dns->ttls_str + ttl_pos, sizeof(dns->ttls_str) - ttl_pos, ", ");
        }
        ans_pos += snprintf(dns->answers_str + ans_pos, sizeof(dns->answers_str) - ans_pos, "%s", dns->answers[i].rdata);
        ttl_pos += snprintf(dns->ttls_str + ttl_pos, sizeof(dns->ttls_str) - ttl_pos, "%u", dns->answers[i].ttl);
    }

    dns->rejected = (dns->rcode == DNS_RCODE_REFUSED);
    dns->is_valid = true;
    return 1;
}

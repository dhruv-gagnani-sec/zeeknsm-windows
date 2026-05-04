/*
 * dns_parser.h - Deep DNS Protocol Parser
 * Parses DNS queries and responses matching Zeek's dns.log schema
 */

#ifndef ZEEK_DNS_PARSER_H
#define ZEEK_DNS_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#define DNS_MAX_NAME_LEN    256
#define DNS_MAX_ANSWERS     32
#define DNS_MAX_QUERY_LEN   512

/* DNS Header */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;  /* Questions */
    uint16_t an_count;  /* Answers */
    uint16_t ns_count;  /* Authority */
    uint16_t ar_count;  /* Additional */
} DNSRawHeader;

/* DNS flags bit masks */
#define DNS_FLAG_QR     0x8000  /* Query/Response */
#define DNS_FLAG_AA     0x0400  /* Authoritative Answer */
#define DNS_FLAG_TC     0x0200  /* Truncated */
#define DNS_FLAG_RD     0x0100  /* Recursion Desired */
#define DNS_FLAG_RA     0x0080  /* Recursion Available */
#define DNS_FLAG_RCODE  0x000F  /* Response Code */
#define DNS_FLAG_OPCODE 0x7800  /* Opcode */

/* DNS Record Types */
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_SRV    33
#define DNS_TYPE_ANY    255

/* DNS Response Codes */
#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP    4
#define DNS_RCODE_REFUSED   5

/* Parsed DNS Answer */
typedef struct {
    char name[DNS_MAX_NAME_LEN];
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    char rdata[DNS_MAX_NAME_LEN]; /* Human-readable rdata */
} DNSAnswer;

/* Parsed DNS Transaction */
typedef struct {
    /* Header fields */
    uint16_t trans_id;
    bool is_response;       /* QR bit */
    int opcode;
    bool authoritative;
    bool truncated;
    bool recursion_desired;
    bool recursion_available;
    int rcode;

    /* Query */
    char query[DNS_MAX_NAME_LEN];
    uint16_t qtype;
    uint16_t qclass;

    /* Answers */
    DNSAnswer answers[DNS_MAX_ANSWERS];
    int answer_count;

    /* Computed fields for Zeek compatibility */
    char qtype_name[16];
    char qclass_name[16];
    char rcode_name[16];
    char answers_str[2048];  /* Comma-separated answer strings */
    char ttls_str[512];      /* Comma-separated TTLs */

    /* Validity */
    bool is_valid;
    bool rejected;           /* Query was rejected */
} ParsedDNS;

/* Parse DNS payload. Returns 1 on success, 0 on failure. */
int dns_parse(const uint8_t *data, int len, ParsedDNS *dns);

/* Get string name for DNS type */
const char *dns_type_name(uint16_t type);

/* Get string name for DNS class */
const char *dns_class_name(uint16_t cls);

/* Get string name for DNS rcode */
const char *dns_rcode_name(int rcode);

/* Check if this looks like a DNS packet (port 53 heuristic + header check) */
bool dns_is_likely(const uint8_t *data, int len);

#endif /* ZEEK_DNS_PARSER_H */

/*
 * protocols.h - Network Protocol Header Definitions & Parsing
 * Covers IPv4, TCP, UDP, ICMP with full field extraction
 */

#ifndef ZEEK_PROTOCOLS_H
#define ZEEK_PROTOCOLS_H

#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma pack(push, 1)

/* ============================================================
 * IPv4 Header
 * ============================================================ */
typedef struct {
    uint8_t  ver_ihl;       /* Version (4 bits) + IHL (4 bits) */
    uint8_t  tos;           /* Type of Service */
    uint16_t total_length;  /* Total Length */
    uint16_t identification;/* Identification */
    uint16_t flags_fragoff; /* Flags (3 bits) + Fragment Offset (13 bits) */
    uint8_t  ttl;           /* Time to Live */
    uint8_t  protocol;      /* Protocol */
    uint16_t checksum;      /* Header Checksum */
    uint32_t src_addr;      /* Source Address */
    uint32_t dst_addr;      /* Destination Address */
} IPv4Header;

#define IP_VERSION(h)    (((h)->ver_ihl >> 4) & 0x0F)
#define IP_IHL(h)        ((h)->ver_ihl & 0x0F)
#define IP_HDR_LEN(h)    (IP_IHL(h) * 4)
#define IP_FLAGS(h)      (ntohs((h)->flags_fragoff) >> 13)
#define IP_FRAGOFF(h)    (ntohs((h)->flags_fragoff) & 0x1FFF)
#define IP_FLAG_DF       0x02
#define IP_FLAG_MF       0x01

/* IP Protocol numbers */
#define PROTO_ICMP       1
#define PROTO_TCP        6
#define PROTO_UDP        17

/* ============================================================
 * TCP Header
 * ============================================================ */
typedef struct {
    uint16_t src_port;      /* Source Port */
    uint16_t dst_port;      /* Destination Port */
    uint32_t seq_num;       /* Sequence Number */
    uint32_t ack_num;       /* Acknowledgment Number */
    uint8_t  data_offset;   /* Data Offset (4 bits) + Reserved (4 bits) */
    uint8_t  flags;         /* Flags */
    uint16_t window;        /* Window Size */
    uint16_t checksum;      /* Checksum */
    uint16_t urgent_ptr;    /* Urgent Pointer */
} TCPHeader;

#define TCP_DATA_OFF(h)  (((h)->data_offset >> 4) & 0x0F)
#define TCP_HDR_LEN(h)   (TCP_DATA_OFF(h) * 4)

/* TCP Flags */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

/* ============================================================
 * UDP Header
 * ============================================================ */
typedef struct {
    uint16_t src_port;      /* Source Port */
    uint16_t dst_port;      /* Destination Port */
    uint16_t length;        /* Length */
    uint16_t checksum;      /* Checksum */
} UDPHeader;

/* ============================================================
 * ICMP Header
 * ============================================================ */
typedef struct {
    uint8_t  type;          /* Type */
    uint8_t  code;          /* Code */
    uint16_t checksum;      /* Checksum */
    uint16_t identifier;    /* Identifier */
    uint16_t seq_number;    /* Sequence Number */
} ICMPHeader;

/* ICMP Types */
#define ZEEK_ICMP_ECHO_REPLY    0
#define ZEEK_ICMP_DEST_UNREACH  3
#define ZEEK_ICMP_REDIRECT      5
#define ZEEK_ICMP_ECHO_REQUEST  8
#define ZEEK_ICMP_TIME_EXCEEDED 11

#pragma pack(pop)

/* ============================================================
 * Parsed Packet Structure
 * ============================================================ */
typedef struct {
    /* Raw data */
    const uint8_t *raw_data;
    int raw_len;

    /* IP layer */
    const IPv4Header *ip;
    int ip_hdr_len;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    /* Transport layer */
    uint8_t proto;          /* PROTO_TCP, PROTO_UDP, PROTO_ICMP */
    union {
        const TCPHeader  *tcp;
        const UDPHeader  *udp;
        const ICMPHeader *icmp;
    } transport;

    /* Transport parsed fields */
    uint16_t src_port;
    uint16_t dst_port;

    /* Application layer payload */
    const uint8_t *payload;
    int payload_len;

    /* Flags */
    int is_valid;           /* 1 if successfully parsed */
    int is_fragment;        /* 1 if IP fragment */
} ParsedPacket;

/* ============================================================
 * Functions
 * ============================================================ */

/* Parse a raw IP packet. Returns 1 on success, 0 on failure. */
int parse_packet(const uint8_t *data, int len, ParsedPacket *pkt);

/* Convert IP address to string */
void ip_to_str(uint32_t ip, char *buf, int buflen);

/* Get protocol name string */
const char *proto_name(uint8_t proto);

/* Get TCP flags as string (e.g., "SYN,ACK") */
void tcp_flags_str(uint8_t flags, char *buf, int buflen);

/* Get service name from port number */
const char *port_to_service(uint16_t port, uint8_t proto);

#endif /* ZEEK_PROTOCOLS_H */

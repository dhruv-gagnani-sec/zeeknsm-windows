/*
 * tls_parser.h - TLS/SSL Handshake Parser
 * Parses TLS ClientHello/ServerHello matching Zeek's ssl.log schema
 * Includes JA3/JA3S fingerprint generation
 */

#ifndef ZEEK_TLS_PARSER_H
#define ZEEK_TLS_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#define TLS_MAX_SNI           256
#define TLS_MAX_CIPHER_NAME   128
#define TLS_MAX_VERSION_NAME  32
#define TLS_MAX_JA3           128
#define TLS_MAX_JA3_RAW       4096
#define TLS_MAX_CIPHERS       128
#define TLS_MAX_EXTENSIONS    64
#define TLS_MAX_EC_CURVES     32
#define TLS_MAX_EC_FORMATS    16
#define TLS_MAX_ALPN          256
#define TLS_MAX_SUBJECT       512
#define TLS_MAX_ISSUER        512

/* TLS Content Types */
#define TLS_CONTENT_CHANGE_CIPHER  20
#define TLS_CONTENT_ALERT          21
#define TLS_CONTENT_HANDSHAKE      22
#define TLS_CONTENT_APP_DATA       23

/* TLS Handshake Types */
#define TLS_HS_CLIENT_HELLO    1
#define TLS_HS_SERVER_HELLO    2
#define TLS_HS_CERTIFICATE     11
#define TLS_HS_SERVER_DONE     14

/* Parsed TLS ClientHello */
typedef struct {
    uint16_t version;               /* TLS version in ClientHello */
    uint16_t cipher_suites[TLS_MAX_CIPHERS];
    int cipher_suite_count;
    uint16_t extensions[TLS_MAX_EXTENSIONS];
    int extension_count;
    uint16_t ec_curves[TLS_MAX_EC_CURVES];
    int ec_curve_count;
    uint8_t ec_point_formats[TLS_MAX_EC_FORMATS];
    int ec_point_format_count;
    char sni[TLS_MAX_SNI];          /* Server Name Indication */
    char alpn[TLS_MAX_ALPN];        /* Application-Layer Protocol */
    
    /* JA3 fingerprint */
    char ja3_raw[TLS_MAX_JA3_RAW];  /* Raw JA3 string */
    char ja3_hash[TLS_MAX_JA3];     /* MD5 hash of JA3 */
    
    bool is_valid;
} TLSClientHello;

/* Parsed TLS ServerHello */
typedef struct {
    uint16_t version;               /* TLS version in ServerHello */
    uint16_t cipher_suite;          /* Selected cipher suite */
    uint16_t extensions[TLS_MAX_EXTENSIONS];
    int extension_count;
    uint8_t ec_point_format;
    
    /* JA3S fingerprint */
    char ja3s_raw[TLS_MAX_JA3_RAW];
    char ja3s_hash[TLS_MAX_JA3];
    
    bool is_valid;
} TLSServerHello;

/* Parsed TLS Certificate (basic) */
typedef struct {
    char subject[TLS_MAX_SUBJECT];
    char issuer[TLS_MAX_ISSUER];
    char serial[128];
    uint32_t not_before;  /* Unix timestamp */
    uint32_t not_after;   /* Unix timestamp */
    bool self_signed;
    bool is_valid;
} TLSCertificate;

/* Combined TLS session info (for ssl.log) */
typedef struct {
    TLSClientHello client_hello;
    TLSServerHello server_hello;
    TLSCertificate certificate;
    
    char version_str[TLS_MAX_VERSION_NAME];
    char cipher_str[TLS_MAX_CIPHER_NAME];
    bool established;
    bool resumed;
} TLSSession;

/* Check if payload looks like a TLS record */
bool tls_is_likely(const uint8_t *data, int len);

/* Parse TLS ClientHello. Returns 1 on success. */
int tls_parse_client_hello(const uint8_t *data, int len, TLSClientHello *hello);

/* Parse TLS ServerHello. Returns 1 on success. */
int tls_parse_server_hello(const uint8_t *data, int len, TLSServerHello *hello);

/* Get TLS record type from payload. Returns -1 if not TLS. */
int tls_get_handshake_type(const uint8_t *data, int len);

/* Get human-readable TLS version string */
const char *tls_version_str(uint16_t version);

/* Get human-readable cipher suite name */
const char *tls_cipher_str(uint16_t cipher);

/* Initialize TLS session */
void tls_session_init(TLSSession *session);

#endif /* ZEEK_TLS_PARSER_H */

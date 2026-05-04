/*
 * http_parser.h - HTTP Protocol Parser
 * Parses HTTP requests and responses matching Zeek's http.log schema
 */

#ifndef ZEEK_HTTP_PARSER_H
#define ZEEK_HTTP_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#define HTTP_MAX_METHOD      16
#define HTTP_MAX_URI         2048
#define HTTP_MAX_HOST        256
#define HTTP_MAX_HEADER_VAL  1024
#define HTTP_MAX_VERSION     16

/* Parsed HTTP Request */
typedef struct {
    /* Request line */
    char method[HTTP_MAX_METHOD];
    char uri[HTTP_MAX_URI];
    char version[HTTP_MAX_VERSION];

    /* Key headers */
    char host[HTTP_MAX_HOST];
    char user_agent[HTTP_MAX_HEADER_VAL];
    char referer[HTTP_MAX_HEADER_VAL];
    char content_type[HTTP_MAX_HEADER_VAL];
    char cookie[HTTP_MAX_HEADER_VAL];
    char authorization[HTTP_MAX_HEADER_VAL];
    char origin[HTTP_MAX_HEADER_VAL];
    char accept[HTTP_MAX_HEADER_VAL];
    char accept_language[HTTP_MAX_HEADER_VAL];
    char accept_encoding[HTTP_MAX_HEADER_VAL];
    char connection[HTTP_MAX_HEADER_VAL];
    char x_forwarded_for[HTTP_MAX_HEADER_VAL];
    int  content_length;

    /* Metadata */
    int  header_length;   /* Total header bytes */
    bool is_valid;
    bool has_body;
} HTTPRequest;

/* Parsed HTTP Response */
typedef struct {
    /* Status line */
    char version[HTTP_MAX_VERSION];
    int  status_code;
    char status_msg[128];

    /* Key headers */
    char server[HTTP_MAX_HEADER_VAL];
    char content_type[HTTP_MAX_HEADER_VAL];
    char content_encoding[HTTP_MAX_HEADER_VAL];
    char location[HTTP_MAX_HEADER_VAL];
    char set_cookie[HTTP_MAX_HEADER_VAL];
    char www_authenticate[HTTP_MAX_HEADER_VAL];
    char transfer_encoding[HTTP_MAX_HEADER_VAL];
    int  content_length;

    /* Metadata */
    int  header_length;
    bool is_valid;
    bool is_chunked;
} HTTPResponse;

/* Parse HTTP request payload. Returns 1 on success. */
int http_parse_request(const uint8_t *data, int len, HTTPRequest *req);

/* Parse HTTP response payload. Returns 1 on success. */
int http_parse_response(const uint8_t *data, int len, HTTPResponse *resp);

/* Check if payload looks like an HTTP request */
bool http_is_request(const uint8_t *data, int len);

/* Check if payload looks like an HTTP response */
bool http_is_response(const uint8_t *data, int len);

/* Get MIME type category for Zeek resp_mime_types field */
const char *http_mime_category(const char *content_type);

#endif /* ZEEK_HTTP_PARSER_H */

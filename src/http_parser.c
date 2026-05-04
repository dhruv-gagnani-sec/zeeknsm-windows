/*
 * http_parser.c - HTTP Protocol Parser Implementation
 */

#include "http_parser.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/* Case insensitive string comparison for n chars */
static int strnicmp_local(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        int ca = tolower((unsigned char)a[i]);
        int cb = tolower((unsigned char)b[i]);
        if (ca != cb) return ca - cb;
        if (ca == 0) return 0;
    }
    return 0;
}

/* Find end of line (\r\n) in data, returns pointer past \r\n */
static const uint8_t *find_eol(const uint8_t *data, int len, int *line_len) {
    for (int i = 0; i < len - 1; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            *line_len = i;
            return data + i + 2;
        }
    }
    /* Try just \n */
    for (int i = 0; i < len; i++) {
        if (data[i] == '\n') {
            *line_len = i;
            return data + i + 1;
        }
    }
    *line_len = len;
    return data + len;
}

/* Copy a line segment into a buffer, null-terminated */
static void copy_field(const char *src, int len, char *dst, int dst_max) {
    int copy_len = len;
    if (copy_len >= dst_max) copy_len = dst_max - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    /* Trim trailing whitespace */
    while (copy_len > 0 && isspace((unsigned char)dst[copy_len - 1])) {
        dst[--copy_len] = '\0';
    }
}

/* Parse a single header line "Name: Value" */
static void parse_header(const char *line, int len, HTTPRequest *req) {
    const char *colon = memchr(line, ':', len);
    if (!colon) return;

    int name_len = (int)(colon - line);
    const char *val = colon + 1;
    int val_len = len - name_len - 1;
    while (val_len > 0 && isspace((unsigned char)*val)) { val++; val_len--; }

    if (name_len == 4 && strnicmp_local(line, "host", 4) == 0) {
        copy_field(val, val_len, req->host, sizeof(req->host));
    } else if (name_len == 10 && strnicmp_local(line, "user-agent", 10) == 0) {
        copy_field(val, val_len, req->user_agent, sizeof(req->user_agent));
    } else if (name_len == 7 && strnicmp_local(line, "referer", 7) == 0) {
        copy_field(val, val_len, req->referer, sizeof(req->referer));
    } else if (name_len == 12 && strnicmp_local(line, "content-type", 12) == 0) {
        copy_field(val, val_len, req->content_type, sizeof(req->content_type));
    } else if (name_len == 14 && strnicmp_local(line, "content-length", 14) == 0) {
        char tmp[32];
        copy_field(val, val_len, tmp, sizeof(tmp));
        req->content_length = atoi(tmp);
        req->has_body = (req->content_length > 0);
    } else if (name_len == 6 && strnicmp_local(line, "cookie", 6) == 0) {
        copy_field(val, val_len, req->cookie, sizeof(req->cookie));
    } else if (name_len == 13 && strnicmp_local(line, "authorization", 13) == 0) {
        copy_field(val, val_len, req->authorization, sizeof(req->authorization));
    } else if (name_len == 6 && strnicmp_local(line, "origin", 6) == 0) {
        copy_field(val, val_len, req->origin, sizeof(req->origin));
    } else if (name_len == 6 && strnicmp_local(line, "accept", 6) == 0) {
        copy_field(val, val_len, req->accept, sizeof(req->accept));
    } else if (name_len == 15 && strnicmp_local(line, "accept-language", 15) == 0) {
        copy_field(val, val_len, req->accept_language, sizeof(req->accept_language));
    } else if (name_len == 15 && strnicmp_local(line, "accept-encoding", 15) == 0) {
        copy_field(val, val_len, req->accept_encoding, sizeof(req->accept_encoding));
    } else if (name_len == 10 && strnicmp_local(line, "connection", 10) == 0) {
        copy_field(val, val_len, req->connection, sizeof(req->connection));
    } else if (name_len == 15 && strnicmp_local(line, "x-forwarded-for", 15) == 0) {
        copy_field(val, val_len, req->x_forwarded_for, sizeof(req->x_forwarded_for));
    }
}

/* Parse a single response header line */
static void parse_resp_header(const char *line, int len, HTTPResponse *resp) {
    const char *colon = memchr(line, ':', len);
    if (!colon) return;

    int name_len = (int)(colon - line);
    const char *val = colon + 1;
    int val_len = len - name_len - 1;
    while (val_len > 0 && isspace((unsigned char)*val)) { val++; val_len--; }

    if (name_len == 6 && strnicmp_local(line, "server", 6) == 0) {
        copy_field(val, val_len, resp->server, sizeof(resp->server));
    } else if (name_len == 12 && strnicmp_local(line, "content-type", 12) == 0) {
        copy_field(val, val_len, resp->content_type, sizeof(resp->content_type));
    } else if (name_len == 16 && strnicmp_local(line, "content-encoding", 16) == 0) {
        copy_field(val, val_len, resp->content_encoding, sizeof(resp->content_encoding));
    } else if (name_len == 14 && strnicmp_local(line, "content-length", 14) == 0) {
        char tmp[32];
        copy_field(val, val_len, tmp, sizeof(tmp));
        resp->content_length = atoi(tmp);
    } else if (name_len == 8 && strnicmp_local(line, "location", 8) == 0) {
        copy_field(val, val_len, resp->location, sizeof(resp->location));
    } else if (name_len == 10 && strnicmp_local(line, "set-cookie", 10) == 0) {
        copy_field(val, val_len, resp->set_cookie, sizeof(resp->set_cookie));
    } else if (name_len == 16 && strnicmp_local(line, "www-authenticate", 16) == 0) {
        copy_field(val, val_len, resp->www_authenticate, sizeof(resp->www_authenticate));
    } else if (name_len == 17 && strnicmp_local(line, "transfer-encoding", 17) == 0) {
        copy_field(val, val_len, resp->transfer_encoding, sizeof(resp->transfer_encoding));
        if (strnicmp_local(resp->transfer_encoding, "chunked", 7) == 0) {
            resp->is_chunked = true;
        }
    }
}

bool http_is_request(const uint8_t *data, int len) {
    if (len < 4) return false;
    /* Check for common HTTP methods */
    return (memcmp(data, "GET ", 4) == 0 ||
            memcmp(data, "POST", 4) == 0 ||
            memcmp(data, "PUT ", 4) == 0 ||
            memcmp(data, "HEAD", 4) == 0 ||
            memcmp(data, "DELE", 4) == 0 ||  /* DELETE */
            memcmp(data, "OPTI", 4) == 0 ||  /* OPTIONS */
            memcmp(data, "PATC", 4) == 0 ||  /* PATCH */
            memcmp(data, "CONN", 4) == 0);   /* CONNECT */
}

bool http_is_response(const uint8_t *data, int len) {
    if (len < 9) return false;
    return (memcmp(data, "HTTP/1.", 7) == 0 || memcmp(data, "HTTP/2", 6) == 0);
}

int http_parse_request(const uint8_t *data, int len, HTTPRequest *req) {
    memset(req, 0, sizeof(HTTPRequest));
    req->content_length = -1;

    if (!http_is_request(data, len)) return 0;

    const uint8_t *pos = data;
    int remaining = len;

    /* Parse request line: METHOD URI HTTP/x.x */
    int line_len;
    const uint8_t *next = find_eol(pos, remaining, &line_len);

    /* Find method */
    const char *line = (const char *)pos;
    const char *sp1 = memchr(line, ' ', line_len);
    if (!sp1) return 0;

    int method_len = (int)(sp1 - line);
    copy_field(line, method_len, req->method, sizeof(req->method));

    /* Find URI */
    const char *uri_start = sp1 + 1;
    int uri_remaining = line_len - method_len - 1;
    const char *sp2 = memchr(uri_start, ' ', uri_remaining);
    
    int uri_len;
    if (sp2) {
        uri_len = (int)(sp2 - uri_start);
        /* Version */
        copy_field(sp2 + 1, line_len - (int)(sp2 + 1 - line), req->version, sizeof(req->version));
    } else {
        uri_len = uri_remaining;
    }
    copy_field(uri_start, uri_len, req->uri, sizeof(req->uri));

    /* Parse headers */
    remaining -= (int)(next - pos);
    pos = next;

    while (remaining > 0) {
        next = find_eol(pos, remaining, &line_len);
        if (line_len == 0) {
            /* Empty line = end of headers */
            req->header_length = (int)(next - data);
            break;
        }
        parse_header((const char *)pos, line_len, req);
        remaining -= (int)(next - pos);
        pos = next;
    }

    req->is_valid = true;
    return 1;
}

int http_parse_response(const uint8_t *data, int len, HTTPResponse *resp) {
    memset(resp, 0, sizeof(HTTPResponse));
    resp->content_length = -1;

    if (!http_is_response(data, len)) return 0;

    const uint8_t *pos = data;
    int remaining = len;

    /* Parse status line: HTTP/x.x STATUS MSG */
    int line_len;
    const uint8_t *next = find_eol(pos, remaining, &line_len);

    const char *line = (const char *)pos;
    const char *sp1 = memchr(line, ' ', line_len);
    if (!sp1) return 0;

    /* Version */
    int ver_len = (int)(sp1 - line);
    copy_field(line, ver_len, resp->version, sizeof(resp->version));

    /* Status code */
    const char *code_start = sp1 + 1;
    int code_remaining = line_len - ver_len - 1;
    char code_str[8] = {0};
    int ci = 0;
    while (ci < code_remaining && ci < 3 && isdigit((unsigned char)code_start[ci])) {
        code_str[ci] = code_start[ci];
        ci++;
    }
    resp->status_code = atoi(code_str);

    /* Status message */
    if (ci < code_remaining && code_start[ci] == ' ') {
        copy_field(code_start + ci + 1, code_remaining - ci - 1, resp->status_msg, sizeof(resp->status_msg));
    }

    /* Parse headers */
    remaining -= (int)(next - pos);
    pos = next;

    while (remaining > 0) {
        next = find_eol(pos, remaining, &line_len);
        if (line_len == 0) {
            resp->header_length = (int)(next - data);
            break;
        }
        parse_resp_header((const char *)pos, line_len, resp);
        remaining -= (int)(next - pos);
        pos = next;
    }

    resp->is_valid = true;
    return 1;
}

const char *http_mime_category(const char *content_type) {
    if (!content_type || content_type[0] == '\0') return "-";
    
    if (strnicmp_local(content_type, "text/html", 9) == 0) return "text/html";
    if (strnicmp_local(content_type, "text/plain", 10) == 0) return "text/plain";
    if (strnicmp_local(content_type, "text/css", 8) == 0) return "text/css";
    if (strnicmp_local(content_type, "text/javascript", 15) == 0) return "application/javascript";
    if (strnicmp_local(content_type, "application/javascript", 22) == 0) return "application/javascript";
    if (strnicmp_local(content_type, "application/json", 16) == 0) return "application/json";
    if (strnicmp_local(content_type, "application/xml", 15) == 0) return "application/xml";
    if (strnicmp_local(content_type, "application/octet", 17) == 0) return "application/octet-stream";
    if (strnicmp_local(content_type, "image/", 6) == 0) return "image";
    if (strnicmp_local(content_type, "video/", 6) == 0) return "video";
    if (strnicmp_local(content_type, "audio/", 6) == 0) return "audio";
    if (strnicmp_local(content_type, "application/pdf", 15) == 0) return "application/pdf";
    if (strnicmp_local(content_type, "application/zip", 15) == 0) return "application/zip";
    
    /* Return as-is up to semicolon */
    static char buf[128];
    const char *semi = strchr(content_type, ';');
    if (semi) {
        int n = (int)(semi - content_type);
        if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
        memcpy(buf, content_type, n);
        buf[n] = '\0';
        return buf;
    }
    return content_type;
}

/*
 * tls_parser.c - TLS/SSL Handshake Parser Implementation
 * Includes JA3/JA3S fingerprint generation with MD5 hashing
 */

#include "tls_parser.h"
#include <stdio.h>
#include <string.h>
#include <winsock2.h>

/* ============================================================
 * Simple MD5 implementation (for JA3 hashing)
 * ============================================================ */
typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
} MD5Context;

static const uint32_t md5_T[] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

#define MD5_F(x,y,z) (((x)&(y))|((~(x))&(z)))
#define MD5_G(x,y,z) (((x)&(z))|((y)&(~(z))))
#define MD5_H(x,y,z) ((x)^(y)^(z))
#define MD5_I(x,y,z) ((y)^((x)|(~(z))))
#define MD5_ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t M[16];
    for (int i=0;i<16;i++) M[i]=block[i*4]|(block[i*4+1]<<8)|(block[i*4+2]<<16)|(block[i*4+3]<<24);
    
    static const int s[]={7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21};
    for (int i=0;i<64;i++) {
        uint32_t f; int g;
        if (i<16)      { f=MD5_F(b,c,d); g=i; }
        else if (i<32) { f=MD5_G(b,c,d); g=(5*i+1)%16; }
        else if (i<48) { f=MD5_H(b,c,d); g=(3*i+5)%16; }
        else           { f=MD5_I(b,c,d); g=(7*i)%16; }
        uint32_t tmp=d; d=c; c=b;
        b=b+MD5_ROTL(a+f+md5_T[i]+M[g], s[(i/16)*4+(i%4)]);
        a=tmp;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
}

static void md5_init(MD5Context *ctx) {
    ctx->state[0]=0x67452301; ctx->state[1]=0xefcdab89;
    ctx->state[2]=0x98badcfe; ctx->state[3]=0x10325476;
    ctx->count=0; memset(ctx->buffer,0,64);
}

static void md5_update(MD5Context *ctx, const uint8_t *data, size_t len) {
    size_t idx = (size_t)(ctx->count % 64);
    ctx->count += len;
    for (size_t i=0; i<len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx==64) { md5_transform(ctx->state, ctx->buffer); idx=0; }
    }
}

static void md5_final(MD5Context *ctx, uint8_t digest[16]) {
    size_t idx = (size_t)(ctx->count % 64);
    ctx->buffer[idx++] = 0x80;
    if (idx>56) { memset(ctx->buffer+idx,0,64-idx); md5_transform(ctx->state,ctx->buffer); idx=0; }
    memset(ctx->buffer+idx,0,56-idx);
    uint64_t bits = ctx->count*8;
    for (int i=0;i<8;i++) ctx->buffer[56+i]=(uint8_t)(bits>>(i*8));
    md5_transform(ctx->state, ctx->buffer);
    for (int i=0;i<4;i++) {
        digest[i*4]=(uint8_t)ctx->state[i]; digest[i*4+1]=(uint8_t)(ctx->state[i]>>8);
        digest[i*4+2]=(uint8_t)(ctx->state[i]>>16); digest[i*4+3]=(uint8_t)(ctx->state[i]>>24);
    }
}

static void md5_hash_string(const char *input, char *output, int outlen) {
    MD5Context ctx;
    uint8_t digest[16];
    md5_init(&ctx);
    md5_update(&ctx, (const uint8_t *)input, strlen(input));
    md5_final(&ctx, digest);
    snprintf(output, outlen, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        digest[0],digest[1],digest[2],digest[3],digest[4],digest[5],digest[6],digest[7],
        digest[8],digest[9],digest[10],digest[11],digest[12],digest[13],digest[14],digest[15]);
}

/* ============================================================
 * GREASE values filter (for JA3)
 * ============================================================ */
static bool is_grease(uint16_t val) {
    return (val & 0x0F0F) == 0x0A0A;
}

/* ============================================================
 * TLS Version Strings
 * ============================================================ */
const char *tls_version_str(uint16_t version) {
    switch (version) {
    case 0x0300: return "SSLv3";
    case 0x0301: return "TLSv10";
    case 0x0302: return "TLSv11";
    case 0x0303: return "TLSv12";
    case 0x0304: return "TLSv13";
    default: {
        static char buf[16];
        snprintf(buf, sizeof(buf), "0x%04x", version);
        return buf;
    }
    }
}

/* ============================================================
 * Common Cipher Suite Names
 * ============================================================ */
const char *tls_cipher_str(uint16_t cipher) {
    switch (cipher) {
    case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
    case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
    case 0x003C: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
    case 0x003D: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
    case 0x009C: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
    case 0x009D: return "TLS_RSA_WITH_AES_256_GCM_SHA384";
    case 0xC013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
    case 0xC014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
    case 0xC027: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
    case 0xC028: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
    case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    case 0xCCA9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
    case 0x1301: return "TLS_AES_128_GCM_SHA256";
    case 0x1302: return "TLS_AES_256_GCM_SHA384";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
    default: {
        static char buf[32];
        snprintf(buf, sizeof(buf), "0x%04x", cipher);
        return buf;
    }
    }
}

/* ============================================================
 * TLS Detection
 * ============================================================ */
bool tls_is_likely(const uint8_t *data, int len) {
    if (len < 6) return false;
    
    /* Check TLS record header: content_type(1) + version(2) + length(2) */
    uint8_t content_type = data[0];
    uint16_t version = (data[1] << 8) | data[2];
    
    if (content_type != TLS_CONTENT_HANDSHAKE &&
        content_type != TLS_CONTENT_CHANGE_CIPHER &&
        content_type != TLS_CONTENT_ALERT &&
        content_type != TLS_CONTENT_APP_DATA) {
        return false;
    }
    
    /* Version should be 0x0300-0x0304 or 0x0301 (common in record layer) */
    if (version < 0x0300 || version > 0x0304) return false;
    
    return true;
}

int tls_get_handshake_type(const uint8_t *data, int len) {
    if (len < 6) return -1;
    if (data[0] != TLS_CONTENT_HANDSHAKE) return -1;
    /* Handshake type is at offset 5 */
    return data[5];
}

/* ============================================================
 * Parse TLS ClientHello
 * ============================================================ */
int tls_parse_client_hello(const uint8_t *data, int len, TLSClientHello *hello) {
    memset(hello, 0, sizeof(TLSClientHello));
    
    if (len < 6) return 0;
    
    /* TLS Record: type(1) + version(2) + length(2) */
    if (data[0] != TLS_CONTENT_HANDSHAKE) return 0;
    int pos = 5;
    
    /* Handshake: type(1) + length(3) */
    if (pos >= len || data[pos] != TLS_HS_CLIENT_HELLO) return 0;
    pos += 4; /* Skip type + 3-byte length */
    
    if (pos + 2 > len) return 0;
    
    /* Client version */
    hello->version = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    
    /* Random (32 bytes) */
    pos += 32;
    if (pos >= len) return 0;
    
    /* Session ID */
    uint8_t sid_len = data[pos++];
    pos += sid_len;
    if (pos + 2 > len) return 0;
    
    /* Cipher Suites */
    uint16_t cs_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    if (pos + cs_len > len) return 0;
    
    int cs_end = pos + cs_len;
    while (pos + 1 < cs_end && hello->cipher_suite_count < TLS_MAX_CIPHERS) {
        uint16_t cs = (data[pos] << 8) | data[pos + 1];
        if (!is_grease(cs)) {
            hello->cipher_suites[hello->cipher_suite_count++] = cs;
        }
        pos += 2;
    }
    pos = cs_end;
    
    /* Compression Methods */
    if (pos >= len) goto build_ja3;
    uint8_t comp_len = data[pos++];
    pos += comp_len;
    
    /* Extensions */
    if (pos + 2 > len) goto build_ja3;
    uint16_t ext_total_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    int ext_end = pos + ext_total_len;
    if (ext_end > len) ext_end = len;
    
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_len  = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        
        if (pos + ext_len > ext_end) break;
        
        if (!is_grease(ext_type)) {
            if (hello->extension_count < TLS_MAX_EXTENSIONS) {
                hello->extensions[hello->extension_count++] = ext_type;
            }
        }
        
        /* SNI (type 0) */
        if (ext_type == 0 && ext_len > 5) {
            int sni_pos = pos + 2; /* Skip SNI list length */
            if (sni_pos < pos + ext_len && data[sni_pos] == 0) { /* host_name type */
                sni_pos++;
                uint16_t name_len = (data[sni_pos] << 8) | data[sni_pos + 1];
                sni_pos += 2;
                if (name_len < TLS_MAX_SNI && sni_pos + name_len <= ext_end) {
                    memcpy(hello->sni, data + sni_pos, name_len);
                    hello->sni[name_len] = '\0';
                }
            }
        }
        
        /* Supported Groups / Elliptic Curves (type 10) */
        if (ext_type == 10 && ext_len >= 2) {
            uint16_t curves_len = (data[pos] << 8) | data[pos + 1];
            int cp = pos + 2;
            int curves_end = cp + curves_len;
            if (curves_end > pos + ext_len) curves_end = pos + ext_len;
            while (cp + 1 < curves_end && hello->ec_curve_count < TLS_MAX_EC_CURVES) {
                uint16_t curve = (data[cp] << 8) | data[cp + 1];
                if (!is_grease(curve)) {
                    hello->ec_curves[hello->ec_curve_count++] = curve;
                }
                cp += 2;
            }
        }
        
        /* EC Point Formats (type 11) */
        if (ext_type == 11 && ext_len >= 1) {
            uint8_t fmt_len = data[pos];
            for (int i = 0; i < fmt_len && i < TLS_MAX_EC_FORMATS && pos + 1 + i < ext_end; i++) {
                hello->ec_point_formats[hello->ec_point_format_count++] = data[pos + 1 + i];
            }
        }
        
        /* ALPN (type 16) */
        if (ext_type == 16 && ext_len >= 2) {
            uint16_t alpn_len = (data[pos] << 8) | data[pos + 1];
            int ap = pos + 2;
            int alpn_end = ap + alpn_len;
            if (alpn_end > pos + ext_len) alpn_end = pos + ext_len;
            int apos = 0;
            while (ap < alpn_end) {
                uint8_t proto_len = data[ap++];
                if (ap + proto_len > alpn_end) break;
                if (apos > 0 && apos < TLS_MAX_ALPN - 1) hello->alpn[apos++] = ',';
                int copy = proto_len;
                if (apos + copy >= TLS_MAX_ALPN) copy = TLS_MAX_ALPN - apos - 1;
                memcpy(hello->alpn + apos, data + ap, copy);
                apos += copy;
                ap += proto_len;
            }
            hello->alpn[apos] = '\0';
        }
        
        pos += ext_len;
    }

build_ja3:
    /* Build JA3 string: TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats */
    {
        int p = 0;
        p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, "%u,", hello->version);
        
        for (int i = 0; i < hello->cipher_suite_count; i++) {
            if (i > 0) p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, "-");
            p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, "%u", hello->cipher_suites[i]);
        }
        p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, ",");
        
        for (int i = 0; i < hello->extension_count; i++) {
            if (i > 0) p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, "-");
            p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, "%u", hello->extensions[i]);
        }
        p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, ",");
        
        for (int i = 0; i < hello->ec_curve_count; i++) {
            if (i > 0) p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, "-");
            p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, "%u", hello->ec_curves[i]);
        }
        p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, ",");
        
        for (int i = 0; i < hello->ec_point_format_count; i++) {
            if (i > 0) p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, "-");
            p += snprintf(hello->ja3_raw + p, sizeof(hello->ja3_raw) - p, "%u", hello->ec_point_formats[i]);
        }
        
        md5_hash_string(hello->ja3_raw, hello->ja3_hash, sizeof(hello->ja3_hash));
    }
    
    hello->is_valid = true;
    return 1;
}

/* ============================================================
 * Parse TLS ServerHello
 * ============================================================ */
int tls_parse_server_hello(const uint8_t *data, int len, TLSServerHello *hello) {
    memset(hello, 0, sizeof(TLSServerHello));
    
    if (len < 6) return 0;
    if (data[0] != TLS_CONTENT_HANDSHAKE) return 0;
    
    int pos = 5;
    if (pos >= len || data[pos] != TLS_HS_SERVER_HELLO) return 0;
    pos += 4;
    
    if (pos + 2 > len) return 0;
    hello->version = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    
    /* Random (32 bytes) */
    pos += 32;
    if (pos >= len) return 0;
    
    /* Session ID */
    uint8_t sid_len = data[pos++];
    pos += sid_len;
    if (pos + 2 > len) return 0;
    
    /* Selected cipher suite */
    hello->cipher_suite = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    
    /* Compression method */
    if (pos >= len) goto build_ja3s;
    pos++;
    
    /* Extensions */
    if (pos + 2 > len) goto build_ja3s;
    uint16_t ext_total_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    int ext_end = pos + ext_total_len;
    if (ext_end > len) ext_end = len;
    
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_len  = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        
        if (!is_grease(ext_type) && hello->extension_count < TLS_MAX_EXTENSIONS) {
            hello->extensions[hello->extension_count++] = ext_type;
        }
        
        pos += ext_len;
    }

build_ja3s:
    /* Build JA3S: TLSVersion,CipherSuite,Extensions */
    {
        int p = 0;
        p += snprintf(hello->ja3s_raw + p, sizeof(hello->ja3s_raw) - p, "%u,%u,", 
                     hello->version, hello->cipher_suite);
        
        for (int i = 0; i < hello->extension_count; i++) {
            if (i > 0) p += snprintf(hello->ja3s_raw + p, sizeof(hello->ja3s_raw) - p, "-");
            p += snprintf(hello->ja3s_raw + p, sizeof(hello->ja3s_raw) - p, "%u", hello->extensions[i]);
        }
        
        md5_hash_string(hello->ja3s_raw, hello->ja3s_hash, sizeof(hello->ja3s_hash));
    }
    
    hello->is_valid = true;
    return 1;
}

void tls_session_init(TLSSession *session) {
    memset(session, 0, sizeof(TLSSession));
}

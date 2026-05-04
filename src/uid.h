/*
 * uid.h - Zeek-compatible Unique Connection ID Generator
 * Generates Base62 encoded unique identifiers matching Zeek's UID format
 */

#ifndef ZEEK_UID_H
#define ZEEK_UID_H

#include <stdint.h>

#define UID_LENGTH 17  /* "C" + 16 random chars + null */

/* Initialize the UID generator (seed RNG) */
void uid_init(void);

/* Generate a new Zeek-style UID into buf (must be >= UID_LENGTH bytes) */
void uid_generate(char *buf);

/* Generate a unique session ID (numeric, for internal tracking) */
uint64_t uid_session_id(void);

#endif /* ZEEK_UID_H */

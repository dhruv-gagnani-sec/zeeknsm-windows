/*
 * uid.c - Zeek-compatible Unique Connection ID Generator
 */

#include "uid.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static const char BASE62_CHARS[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static volatile LONG uid_counter = 0;
static uint64_t session_counter = 0;

void uid_init(void) {
    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);
    srand((unsigned int)(time(NULL) ^ perf.LowPart ^ GetCurrentProcessId()));
}

void uid_generate(char *buf) {
    LONG count = InterlockedIncrement(&uid_counter);
    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);
    
    /* Seed with mix of counter, performance counter, and random */
    uint64_t seed = ((uint64_t)perf.QuadPart << 16) ^ ((uint64_t)count << 8) ^ rand();
    
    buf[0] = 'C';  /* Zeek UIDs start with 'C' for connections */
    
    for (int i = 1; i < UID_LENGTH - 1; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL; /* LCG */
        buf[i] = BASE62_CHARS[(seed >> 33) % 62];
    }
    buf[UID_LENGTH - 1] = '\0';
}

uint64_t uid_session_id(void) {
    return InterlockedIncrement64((volatile LONG64 *)&session_counter);
}

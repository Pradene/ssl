#ifndef FT_SSL_H
#define FT_SSL_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <endian.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct {
    uint64_t blocks_size;
    uint32_t length_size;
    uint32_t length_endian;
} HashConfig;

typedef struct {
    char     *data;
    uint64_t  blocks_size;
    uint64_t  blocks_count;
} MDBuffer;

typedef struct {
    const char  *name;
    const char  *description;
    void        (*handler)(void);
} Option;

typedef struct {
    const char  *name;
    void        (*handler)(const char *input);
} Command;

// Preprocessing
MDBuffer  merkle_damgard_preprocess(const char *src, HashConfig config);

// Parsing
Command *parse_command(u32 argc, char *argv[]);
u32     parse_options(u32 argc, char *argv[]);

// Algorithms
void sha256(const char *string);
void md5(const char *s);

// Utils
u32 rotu32l(u32 value, u32 amount);
u32 rotu32r(u32 value, u32 amount);

#endif // FT_SSL_H

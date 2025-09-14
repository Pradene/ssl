#ifndef FT_SSL_H
#define FT_SSL_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

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
MDBuffer  md_strengthening(const char *src, uint64_t blocks_size);

// Parsing
Command *parse_command(int argc, char *argv[]);
int     parse_options(int argc, char *argv[]);

// Algorithms
void sha256(const char *string);
void md5(const char *s);

#endif // FT_SSL_H

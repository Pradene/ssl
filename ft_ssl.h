#ifndef FT_SSL_H
#define FT_SSL_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct {
    const char  *name;
    const char  *description;
    void        (*handler)(void);
} Option;

typedef struct {
    const char  *name;
    void        (*handler)(const char *input);
} Command;

// Global variables (declared as extern)
extern bool quiet;
extern bool print_input;
extern bool reverse;
extern bool print_sum;
extern Command commands[];
extern Option options[];

int parse_options(int argc, char *argv[]);

// Help and utility functions
void print_buffer(char *buffer, uint64_t size);

// Algorithms
void sha256(const char *string);
void md5(const char *s);

#endif // FT_SSL_H

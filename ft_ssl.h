#ifndef FT_SSL_H
#define FT_SSL_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef enum {
    MD5,
    SHA256,
    UNDEFINED,
} Algorithm;

typedef struct {
    const char  *name;
    const char  *description;
    void        (*handler)(void);
} Option;

typedef struct {
    const char  *name;
    Algorithm   algorithm;
} Command;

// Global variables (declared as extern)
extern Algorithm algorithm;
extern bool quiet;
extern bool print_input;
extern bool reverse;
extern bool print_sum;
extern Command commands[];
extern Option options[];

int parse_options(int argc, char *argv[]);

// Option handlers
void set_print(void);
void set_quiet(void);
void set_reverse(void);
void set_sum(void);

// Help and utility functions
void print_help(void);
void print_buffer(char *buffer, uint64_t size);

void md5(const char *s);

#endif // FT_SSL_H

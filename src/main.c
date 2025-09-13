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
  algorithm   algo;
} Command;

static inline uint64_t align(uint64_t size, uint64_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

Algorithm algorithm = UNDEFINED;

// Global variables for options
bool quiet = false;
bool print_input = false;
bool reverse = false;
bool print_sum = false;

Command commands[] = {
  {"md5", MD5},
  {"sha256", SHA256},
  {NULL, 0}
};

// Handler functions
void set_print()   { print_input = true; }
void set_quiet()   { quiet = true; }
void set_reverse() { reverse = true; }
void set_sum()     { print_sum = true; }

Option options[] = {
  {"-p", "Print STDIN to STDOUT", set_print},
  {"-q", "Quiet mode", set_quiet},
  {"-r", "Reverse output format", set_reverse},
  {"-s", "Print the sum of the given string", set_sum},
  {NULL, NULL, NULL}
};

// Parse all options to set global variables
// Return the end of options offset
int parser_options(int argc, char *argv[]) {
  int   offset;
  bool  is_flag = false;

  for (offset = 0; offset < argc; ++offset) {
    for (Option *opt = options; opt->name; opt++) {
      if (strcmp(argv[offset], opt->name) == 0) {
        opt->handler();
        is_flag = true;
        break;
      }
    }

    if (!is_flag) {
      break;
    }
  }

  return (offset);
}

const char usage[] = "\
Usage: ./ft_ssl command [flags] string\n\
";

void print_help(void) {
  write(2, usage, strlen(usage));
}

const int32_t k[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

int main(int argc, char *argv[]) {
  if (argc < 2) {
    print_help();
    return (EXIT_FAILURE);
  }

  argc -= 1;
  argv += 1;
  for (Command *cmd = commands; cmd->name; ++cmd) {
    if (strcmp(*argv, cmd->name) == 0) {
      algorithm = cmd->algo;
      argc -= 1;
      argv += 1;
      break;
    }
  }

  if (algorithm == UNDEFINED) {
    return (EXIT_FAILURE);
  }

  argv += parser_options(argc, argv);
  uint64_t input_size = strlen(*argv);
  uint64_t aligned_size = align(input_size + 1 + 64, 512);
  printf("Aligned size: %lu\n", aligned_size);

  return (EXIT_SUCCESS);
}


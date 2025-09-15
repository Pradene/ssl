#include "ft_ssl.h"

// Flags global variables
extern bool quiet;
extern bool print_input;
extern bool reverse;
extern bool print_sum;

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: ft_ssl command [flags] string\n");
    exit(EXIT_FAILURE);
  }

  argc -= 1;
  argv += 1;

  Command *command = parse_command(argc, argv);
  if (command == NULL) {
    fprintf(stderr, "ft_ssl: error: '%s' is an invalid command\n", *argv);
    exit(EXIT_FAILURE);
  }

  argc -= 1;
  argv += 1;

  u32 offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  while (argc) {
    command->handler(*argv);
    argc -= 1;
    argv += 1;
  }

  return (0);
}


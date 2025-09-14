#include "ft_ssl.h"

// Global variables
extern bool quiet;
extern bool print_input;
extern bool reverse;
extern bool print_sum;

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: ft_ssl command [flags] string\n");
    return (EXIT_FAILURE);
  }

  argc -= 1;
  argv += 1;

  Command *command = parse_command(argc, argv);
  if (command == NULL) {
    fprintf(stderr, "ft_ssl: error: '%s' is an invalid command\n", *argv);
    return (EXIT_FAILURE);
  }

  argc -= 1;
  argv += 1;

  int offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  while (argc) {
    command->handler(*argv);
    argc -= 1;
    argv += 1;
  }

  return (EXIT_SUCCESS);
}


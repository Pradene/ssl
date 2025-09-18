#include "ft_ssl.h"

// Flags global variables
extern bool quiet;
extern bool print_input;
extern bool reverse;
extern bool print_sum;

int main(int argc, char *argv[]) {
  if (argc < 2) {
    ft_fprintf(stderr, "usage: ft_ssl command [flags] [string/file...]\n");
    exit(EXIT_FAILURE);
  }

  argc -= 1;
  argv += 1;

  Command *command = parse_command(argc, argv);
  if (command == NULL) {
    ft_fprintf(stderr, "ft_ssl: error: '%s' is an invalid command\n", *argv);
    exit(EXIT_FAILURE);
  }

  argc -= 1;
  argv += 1;

  u32 offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  if (print_sum && (u32)argc != 0) {
    for (u32 i = 0; i < (u32)argc; ++i) {
      hash_string(argv[i], command->algorithm);
    }
    return (0);
  }

  if (argc > 0) {
    for (u32 i = 0; i < (u32)argc; ++i) {
      hash_file(argv[i], command->algorithm);
    }
  } else {
    hash_stdin(command->algorithm);
  }

  return (0);
}
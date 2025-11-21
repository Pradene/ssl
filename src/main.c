#include "ft_ssl.h"

// Flags global variables
extern bool print_stdin; // -p
extern bool reverse;     // -r
extern bool string;      // -s
extern bool quiet;       // -q

int main(int argc, char *argv[]) {
  if (argc < 2) {
    ft_fprintf(stderr, "usage: ft_ssl command [flags] [string/file...]\n");
    exit(EXIT_FAILURE);
  }

  --argc;
  ++argv;

  Command *command = parse_command(argc, argv);
  if (command == NULL) {
    ft_fprintf(stderr, "ft_ssl: error: '%s' is an invalid command\n", *argv);
    exit(EXIT_FAILURE);
  }

  --argc;
  ++argv;

  u32 offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  // If -p flag set, read stdin first (only once)
  if (print_stdin) {
    hash_stdin(command->algorithm);
  }

  // Handle -s flag: hash one string, then process remaining args as files
  bool processed = false;
  if (string && argc > 0) {
    hash_string(argv[0], command->algorithm);
    --argc;
    ++argv;
    processed = true;
  }

  // Process remaining arguments as files
  if (argc > 0) {
    for (u32 i = 0; i < (u32)argc; ++i) {
      hash_file(argv[i], command->algorithm);
    }
    processed = true;
  }

  // If nothing was processed and -p not set, read from stdin
  if (!processed && !print_stdin) {
    hash_stdin(command->algorithm);
  }

  return (0);
}

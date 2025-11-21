#include "ft_ssl.h"

// Flags global variables
extern bool print_stdin;
extern bool reverse;
extern bool string;
extern bool quiet;

static int stdin_has_data(void) {
  fd_set          readfds;
  struct timeval  tv;

  FD_ZERO(&readfds);
  FD_SET(STDIN_FILENO, &readfds);

  tv.tv_sec = 0;
  tv.tv_usec = 0;

  return (select(1, &readfds, NULL, NULL, &tv) > 0);
}

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

  // Read from stdin only if data is available (non-blocking)
  if (stdin_has_data()) {
    hash_stdin(command->algorithm);
  }

  // Handle -s flag: hash one string, then process remaining args as files
  if (string && argc > 0) {
    hash_string(argv[0], command->algorithm);
    argc -= 1;
    argv += 1;
  }

  // Process remaining arguments as files
  if (argc > 0) {
    for (u32 i = 0; i < (u32)argc; ++i) {
      hash_file(argv[i], command->algorithm);
    }
  } else {
    // No files/strings: block on stdin read
    hash_stdin(command->algorithm);
  }

  return (0);
}
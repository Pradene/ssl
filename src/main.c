#include "ft_ssl.h"

void print_help(void) {
  const char usage[] = "Usage: ./ft_ssl command [flags] string\n";
  write(2, usage, strlen(usage));
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    print_help();
    return (EXIT_FAILURE);
  }

  argc -= 1;
  argv += 1;

  Command *command = parse_command(argc, argv);
  if (command == NULL) {
    print_help();
    return (EXIT_FAILURE);
  }

  argc -= 1;
  argv += 1;

  // Parse options
  int offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  command->handler(*argv);
  return (EXIT_SUCCESS);
}


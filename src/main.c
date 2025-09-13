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

  // Parse command
  for (Command *cmd = commands; cmd->name; ++cmd) {
    if (strcmp(*argv, cmd->name) == 0) {
      algorithm = cmd->algorithm;
      argc -= 1;
      argv += 1;
      break;
    }
  }

  if (algorithm == UNDEFINED) {
    print_help();
    return (EXIT_FAILURE);
  }

  // Parse options
  argv += parse_options(argc, argv);

  md5(*argv);
  return (EXIT_SUCCESS);
}


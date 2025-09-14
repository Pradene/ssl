#include "ft_ssl.h"

Command commands[] = {
    {"md5", md5},
    {"sha256", sha256},
    {NULL, NULL}
};

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
  Command *command = NULL;
  for (Command *cmd = commands; cmd->name; ++cmd) {
    if (strcmp(*argv, cmd->name) == 0) {
      command = cmd;
      argc -= 1;
      argv += 1;
      break;
    }
  }

  if (command == NULL) {
    print_help();
    return (EXIT_FAILURE);
  }

  // Parse options
  int offset = parse_options(argc, argv);
  argc -= offset;
  argv += offset;

  command->handler(*argv);
  return (EXIT_SUCCESS);
}


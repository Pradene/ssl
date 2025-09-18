#include "ft_ssl.h"

bool quiet = false;
bool print_input = false;
bool reverse = false;
bool print_sum = false;

void set_print(void) { print_input = true; }
void set_quiet(void) { quiet = true; }
void set_reverse(void) { reverse = true; }
void set_sum(void) { print_sum = true; }

Option options[] = {
  {"-p", "Print STDIN to STDOUT", set_print},
  {"-q", "Quiet mode", set_quiet},
  {"-r", "Reverse output format", set_reverse},
  {"-s", "Print the sum of the given string", set_sum},
  {NULL, NULL, NULL}
};

u32 parse_options(u32 argc, char *argv[]) {
  u32   offset;
  bool  is_flag = false;

  for (offset = 0; offset < argc; ++offset) {
    is_flag = false;
    for (Option *opt = options; opt->name; opt++) {
      if (ft_strcmp(argv[offset], opt->name) == 0) {
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

Command commands[] = {
  {"md5", &md5_algorithm},
  {"sha256", &sha256_algorithm},
  {"sha512", &sha512_algorithm},
  {NULL, NULL}
};

Command* parse_command(u32 argc, char *argv[]) {
  if (argc < 1) {
    return (NULL);
  }

  for (Command *cmd = commands; cmd->name; ++cmd) {
    if (ft_strcmp(argv[0], cmd->name) == 0) {
      return (cmd);
    }
  }

  return (NULL);
}

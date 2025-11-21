#include "ft_ssl.h"

static void print_digest(const u8* digest, u64 size) {
  for (u64 i = 0; i < size; ++i) {
    ft_printf("%02x", digest[i]);
  }
}

void output_digest(const u8 *digest, u32 size, const char *input, const char *algorithm_name, int input_type) {
  // input_type:
  // 0 = no input,
  // 1 = string (-s flag),
  // 2 = file,
  // 3 = stdin

  if (!quiet) {
    if (reverse) {
      print_digest(digest, size);
      if (input) {
        if (input_type == 1) {
          ft_printf(" '%s'", input);
        } else if (input_type == 2) {
          ft_printf(" %s", input);
        } else {
          if (print_stdin) {
            ft_printf(" ('%s')", input);
          } else {
            ft_printf(" (stdin)");
          }
        }
      }
      ft_printf("\n");
    } else {
      if (input_type == 1) {
        ft_printf("%s ('%s') = ", algorithm_name, input);
        print_digest(digest, size);
      } else if (input_type == 2) {  // file
        ft_printf("%s (%s) = ", algorithm_name, input);
        print_digest(digest, size);
      } else {  // no input
        if (print_stdin) {
          ft_printf("('%s') = ", input);
        } else {
          ft_printf("(stdin) = ");
        }
        print_digest(digest, size);
      }
      ft_printf("\n");
    }
  } else {
    if (input_type == 3 && print_stdin) {
      ft_printf("%s\n", input);
    }
    print_digest(digest, size);
    ft_printf("\n");
  }
}

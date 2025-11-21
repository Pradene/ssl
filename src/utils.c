#include "ft_ssl.h"

void print_digest(const u8 *digest, u32 size, const char *input, const char *algorithm_name, bool is_string) {
  if (!quiet) {
    if (reverse) {
      for (u32 i = 0; i < size; ++i) {
        ft_printf("%02x", digest[i]);
      }
      if (input) {
        if (is_string) {
          ft_printf("='%s'", input);
        } else {
          ft_printf("=%s", input);
        }
      }
      ft_printf("\n");
    } else {
      ft_printf("%s", algorithm_name);
      if (input) {
        if (is_string) {
          ft_printf("('%s')", input);
        } else {
          ft_printf("(%s)", input);
        }
      }
      ft_printf("=");
      for (u32 i = 0; i < size; ++i) {
        ft_printf("%02x", digest[i]);
      }
      ft_printf("\n");
    }
  } else {
    for (u32 i = 0; i < size; ++i) {
      ft_printf("%02x", digest[i]);
    }
    ft_printf("\n");
  }
}
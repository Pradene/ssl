#include "ft_ssl.h"

inline u64 to_endian64(u64 value, u32 target_endian) {
  if ((target_endian == __ORDER_LITTLE_ENDIAN__ && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||
      (target_endian == __ORDER_BIG_ENDIAN__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) {
    return (__builtin_bswap64(value));
  }
  return (value);
}

void print_digest(const u8 *digest, u32 size, const char *input, const char *algorithm_name) {
  if (!quiet) {
    if (reverse) {
      for (u32 i = 0; i < size; ++i) {
        ft_printf("%02x", digest[i]);
      }
      if (input) {
        ft_printf(" \"%s\"\n", input);
      } else {
        ft_printf("\n");
      }
    } else {
      ft_printf("%s", algorithm_name);
      if (input) {
        ft_printf("(\"%s\") = ", input);
      } else {
        ft_printf(" = ");
      }
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
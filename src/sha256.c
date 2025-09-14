#include "ft_ssl.h"

void sha256(const char *string) {
  MDBuffer  buffer = md_strengthening(string, 64);
  free(buffer.data);
}

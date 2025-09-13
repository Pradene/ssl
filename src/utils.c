#include "ft_ssl.h"

void print_buffer(char *buffer, uint64_t size) {
  for (uint64_t i = 0; i < size; i++) {
    uint8_t byte = (uint8_t)buffer[i];
    for (int i = 7; i >= 0; --i) {
      printf("%d", (byte >> i) & 1);
    }
    printf(" ");

    // Add separator every 8 bytes
    if ((i + 1) % 8 == 0 && i + 1 < size) {
      printf("\n");
    }
  }
  printf("\n");
}


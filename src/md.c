#include "ft_ssl.h"

static inline uint64_t align(uint64_t size, uint64_t alignment) {
  return (size + alignment - 1) & ~(alignment - 1);
}


MDBuffer  md_strengthening(const char *src, uint64_t blocks_size, uint32_t length_endian) {
  MDBuffer  buffer = {0};
  uint64_t  src_length = strlen(src);
  uint64_t  src_length_bits = src_length * 8;

  uint64_t  size = align(src_length + 1 + sizeof(uint64_t), blocks_size);
  buffer.blocks_size = blocks_size;
  buffer.blocks_count = size / blocks_size;
  buffer.data = (char *)malloc(sizeof(char) * size);
  if (buffer.data == NULL) {
    const char error_msg[] = "Memory allocation failed\n";
    write(2, error_msg, strlen(error_msg));
    exit(EXIT_FAILURE);
  }

  memcpy(buffer.data, src, src_length);
  memset(buffer.data + src_length, 0x80, 1);
  memset(buffer.data + src_length + 1, 0x00, size - src_length - 1 - sizeof(uint64_t));
  if (length_endian == LITTLE_ENDIAN) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    memcpy(buffer.data + size - sizeof(uint64_t), &src_length_bits, sizeof(uint64_t));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint64_t swapped = __builtin_bswap64(src_length_bits);
    memcpy(buffer.data + size - sizeof(uint64_t), &swapped, sizeof(uint64_t));
#endif
  } else {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint64_t swapped = __builtin_bswap64(src_length_bits);
    memcpy(buffer.data + size - sizeof(uint64_t), &swapped, sizeof(uint64_t));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    memcpy(buffer.data + size - sizeof(uint64_t), &src_length_bits, sizeof(uint64_t));
#endif
  }
  return (buffer);
}

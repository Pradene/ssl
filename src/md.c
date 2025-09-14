#include "ft_ssl.h"

static inline uint64_t to_endian(uint64_t value, uint32_t target_endian) {
  if ((target_endian == LITTLE_ENDIAN && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||
      (target_endian == BIG_ENDIAN && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) {
    return (__builtin_bswap64(value));
  }
  return (value);
}

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
  uint64_t length = to_endian(src_length_bits, length_endian);
  memcpy(buffer.data + size - sizeof(uint64_t), &length, sizeof(uint64_t));
  return (buffer);
}

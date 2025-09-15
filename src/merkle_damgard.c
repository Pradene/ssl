#include "ft_ssl.h"

static inline u64 to_endian(u64 value, u32 target_endian) {
  if ((target_endian == LITTLE_ENDIAN && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||
      (target_endian == BIG_ENDIAN && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) {
    return (__builtin_bswap64(value));
  }
  return (value);
}

static inline u64 align(u64 size, u64 alignment) {
  return (size + alignment - 1) & ~(alignment - 1);
}

MDBuffer  merkle_damgard_preprocess(const char *src, HashConfig config) {
  MDBuffer  buffer = {0};
  u64  src_length = ft_strlen(src);
  u64  src_length_bits = src_length * 8;

  u64  size = align(src_length + 1 + config.length_size, config.blocks_size);
  buffer.blocks_size = config.blocks_size;
  buffer.blocks_count = size / config.blocks_size;
  buffer.data = (char *)malloc(sizeof(char) * size);
  if (buffer.data == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  u64  length = to_endian(src_length_bits, config.length_endian);

  ft_memcpy(buffer.data, src, src_length);
  ft_memset(buffer.data + src_length, 0x80, 1);
  ft_memset(buffer.data + src_length + 1, 0x00, size - src_length - 1 - config.length_size);
  ft_memcpy(buffer.data + size - config.length_size, &length, config.length_size);
  return (buffer);
}

#include "ft_ssl.h"

static const uint32_t k[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint32_t s[64] = {
  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

static const uint32_t h0 = 0x67452301;
static const uint32_t h1 = 0xefcdab89;
static const uint32_t h2 = 0x98badcfe;
static const uint32_t h3 = 0x10325476;

// MD5 helper functions
static inline uint32_t f_round1(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) | ((~x) & z));
}

static inline uint32_t f_round2(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & z) | (y & (~z)));
}

static inline uint32_t f_round3(uint32_t x, uint32_t y, uint32_t z) {
    return (x ^ y ^ z);
}

static inline uint32_t f_round4(uint32_t x, uint32_t y, uint32_t z) {
    return (y ^ (x | (~z)));
}

static uint32_t (*f_functions[4])(uint32_t, uint32_t, uint32_t) = {
    f_round1, f_round2, f_round3, f_round4
};

static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z, uint32_t i) {
    return f_functions[i / 16](x, y, z);
}

static const uint32_t g_lookup[64] = {
  // Round 1: i
  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
  // Round 2: (5*i + 1) % 16
  1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
  // Round 3: (3*i + 5) % 16
  5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
  // Round 4: (7*i) % 16
  0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9
};

static inline uint32_t G(uint32_t i) {
    return g_lookup[i];
}

static inline uint32_t rotate(uint32_t value, uint32_t amount) {
  return (value << amount) | (value >> (32 - amount));
}

void md5(const char *string) {
  MDBuffer  buffer = md_strengthening(string, 64);

  uint32_t  A = h0;
  uint32_t  B = h1;
  uint32_t  C = h2;
  uint32_t  D = h3;

  for (uint64_t chunk = 0; chunk < buffer.blocks_count; ++chunk) {
    uint32_t w[16];
    // Break chunk into sixteen 32-bit little-endian words
    for (uint32_t i = 0; i < 16; ++i) {
      w[i] = ((uint32_t)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 0] <<  0) |
             ((uint32_t)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 1] <<  8) |
             ((uint32_t)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 2] << 16) |
             ((uint32_t)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 3] << 24);
    }

    uint32_t a = A;
    uint32_t b = B;
    uint32_t c = C;
    uint32_t d = D;

    for (uint32_t i = 0; i < 64; ++i) {
      uint32_t f;
      uint32_t g;

      f = F(b, c, d, i);
      g = G(i);

      f = f + a + k[i] + w[g];
      a = d;
      d = c;
      c = b;
      b = b + rotate(f, s[i]);
    }

    A += a;
    B += b;
    C += c;
    D += d;
  }

  printf("%.8x%.8x%.8x%.8x\n",
         __builtin_bswap32(A),
         __builtin_bswap32(B),
         __builtin_bswap32(C),
         __builtin_bswap32(D)
  );

  free(buffer.data);
}

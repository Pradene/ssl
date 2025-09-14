#include "ft_ssl.h"

static const uint32_t h0 = 0x6a09e667;
static const uint32_t h1 = 0xbb67ae85;
static const uint32_t h2 = 0x3c6ef372;
static const uint32_t h3 = 0xa54ff53a;
static const uint32_t h4 = 0x510e527f;
static const uint32_t h5 = 0x9b05688c;
static const uint32_t h6 = 0x1f83d9ab;
static const uint32_t h7 = 0x5be0cd19;

static const uint32_t k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotate_right(uint32_t value, uint32_t amount) {
  return (value >> amount) | (value << (32 - amount));
}

void sha256(const char *string) {
  MDBuffer  buffer = md_strengthening(string, 64, BIG_ENDIAN);

  uint32_t  A = h0;
  uint32_t  B = h1;
  uint32_t  C = h2;
  uint32_t  D = h3;
  uint32_t  E = h4;
  uint32_t  F = h5;
  uint32_t  G = h6;
  uint32_t  H = h7;

  for (uint32_t chunk = 0; chunk < buffer.blocks_count; ++chunk) {
    uint32_t w[64];

    for (uint32_t i = 0; i < 16; ++i) {
      w[i] = ((uint32_t)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 0] << 24) |
             ((uint32_t)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 1] << 16) |
             ((uint32_t)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 2] <<  8) |
             ((uint32_t)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 3] <<  0);
    }
    for (uint32_t i = 16; i < 64; ++i) {
      uint32_t s0 = (rotate_right(w[i-15], 7)) ^ (rotate_right(w[i-15], 18)) ^ (w[i-15] >> 3);
      uint32_t s1 = (rotate_right(w[i-2], 17)) ^ (rotate_right(w[i-2], 19)) ^ (w[i-2] >> 10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t  a = A;
    uint32_t  b = B;
    uint32_t  c = C;
    uint32_t  d = D;
    uint32_t  e = E;
    uint32_t  f = F;
    uint32_t  g = G;
    uint32_t  h = H;

    for (uint32_t i = 0; i < 64; ++i) {
      uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
      uint32_t ch = (e & f) ^ ((~e) & g);
      uint32_t t1 = h + s1 + ch + k[i] + w[i];
      uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
      uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = s0 + mj;


      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    A += a;
    B += b;
    C += c;
    D += d;
    E += e;
    F += f;
    G += g;
    H += h;
  }

  printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", A, B, C, D, E, F, G, H);

  free(buffer.data);
}

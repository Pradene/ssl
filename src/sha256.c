#include "ft_ssl.h"

static const HashConfig SHA256_CONFIG = {
  .blocks_size = 64,
  .length_size = sizeof(u64),
  .length_endian = BIG_ENDIAN
};

static const u32 k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256(const char *string) {
  MDBuffer  buffer = merkle_damgard_preprocess(string, SHA256_CONFIG);

  u32 A = 0x6a09e667;
  u32 B = 0xbb67ae85;
  u32 C = 0x3c6ef372;
  u32 D = 0xa54ff53a;
  u32 E = 0x510e527f;
  u32 F = 0x9b05688c;
  u32 G = 0x1f83d9ab;
  u32 H = 0x5be0cd19;

  for (u32 chunk = 0; chunk < buffer.blocks_count; ++chunk) {
    u32 w[64];

    for (u32 i = 0; i < 16; ++i) {
      // Break chunk into sixteen 32-bit big-endian words
      w[i] = ((u32)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 0] << 24) |
             ((u32)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 1] << 16) |
             ((u32)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 2] <<  8) |
             ((u32)(unsigned char)buffer.data[buffer.blocks_size*chunk + i*4 + 3] <<  0);
    }
    for (u32 i = 16; i < 64; ++i) {
      u32 s0 = (rotu32r(w[i-15], 7)) ^ (rotu32r(w[i-15], 18)) ^ (w[i-15] >> 3);
      u32 s1 = (rotu32r(w[i-2], 17)) ^ (rotu32r(w[i-2], 19)) ^ (w[i-2] >> 10);
      w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    u32  a = A;
    u32  b = B;
    u32  c = C;
    u32  d = D;
    u32  e = E;
    u32  f = F;
    u32  g = G;
    u32  h = H;

    const u32 SHA256_ROUNDS = 64;
    for (u32 i = 0; i < SHA256_ROUNDS; ++i) {
      u32 s1 = rotu32r(e, 6) ^ rotu32r(e, 11) ^ rotu32r(e, 25);
      u32 ch = (e & f) ^ ((~e) & g);
      u32 t1 = h + s1 + ch + k[i] + w[i];
      u32 s0 = rotu32r(a, 2) ^ rotu32r(a, 13) ^ rotu32r(a, 22);
      u32 mj = (a & b) ^ (a & c) ^ (b & c);
      u32 t2 = s0 + mj;

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

#include "ft_ssl.h"

static u32 SHA256_STATE[8] = {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19
};

static MerkleConfig sha256_config = {
  .length_size = 8,
  .length_endian = __ORDER_BIG_ENDIAN__,
  .compress = sha256_compress,
  .initial_state = (u8 *)SHA256_STATE,
  .state_words = 8,
  .word_size = sizeof(u32),
};

const HashAlgorithm sha256_algorithm = {
  .name = "SHA256",
  .type = HASH_TYPE_MERKLE_DAMGARD,
  .config = &sha256_config,
  .digest_size = 32,
  .block_size = 64,
  .state_size = 32, // 8 words * 4 bytes
  .init = merkle_damgard_init,
  .update = merkle_damgard_update,
  .finalize = merkle_damgard_finalize,
  .reset = merkle_damgard_reset
};

static const u32 sha256_k[64] = {
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

void sha256_compress(void *_state, const u8 *block) {
  u32 *state = (u32 *)_state;
  u32 w[64];
  u32 a, b, c, d, e, f, g, h;

  // Prepare message schedule
  for (u32 i = 0; i < 16; ++i) {
    w[i] = ((u32)block[i*4 + 0] << 24) |
           ((u32)block[i*4 + 1] << 16) |
           ((u32)block[i*4 + 2] <<  8) |
           ((u32)block[i*4 + 3] <<  0);
  }
  
  for (u32 i = 16; i < 64; ++i) {
    u32 s0 = ROTR32(w[i-15], 7) ^ ROTR32(w[i-15], 18) ^ (w[i-15] >> 3);
    u32 s1 = ROTR32(w[i-2], 17) ^ ROTR32(w[i-2], 19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }

  // Initialize working variables
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  // Main loop
  for (u32 i = 0; i < 64; ++i) {
    u32 s1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
    u32 ch = (e & f) ^ ((~e) & g);
    u32 t1 = h + s1 + ch + sha256_k[i] + w[i];
    u32 s0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
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

  // Update state
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

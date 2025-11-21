#include "ft_ssl.h"

static u32 SHA224_STATE[8] = {
  0xc1059ed8,
  0x367cd507,
  0x3070dd17,
  0xf70e5939,
  0xffc00b31,
  0x68581511,
  0x64f98fa7,
  0xbefa4fa4
};

static MerkleConfig sha224_config = {
  .length_size = 8,
  .length_endian = __ORDER_BIG_ENDIAN__,
  .compress = sha256_compress,
  .initial_state = (u8 *)SHA224_STATE,
  .state_words = 8,
  .word_size = sizeof(u32),
};

HashAlgorithm sha224_algorithm = {
  .name = "SHA2-224",
  .type = HASH_TYPE_MERKLE_DAMGARD,
  .config = &sha224_config,
  .digest_size = 28,
  .block_size = 64,
  .state_size = 32,
  .init = merkle_damgard_init,
  .update = merkle_damgard_update,
  .finalize = merkle_damgard_finalize,
  .reset = merkle_damgard_reset
};

#include "ft_ssl.h"

static u64 SHA384_STATE[8] = {
  0xcbbb9d5dc1059ed8,
  0x629a292a367cd507,
  0x9159015a3070dd17,
  0x152fecd8f70e5939,
  0x67332667ffc00b31,
  0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7,
  0x47b5481dbefa4fa4
};

static MerkleConfig sha384_config = {
  .length_size = 16,
  .length_endian = __ORDER_BIG_ENDIAN__,
  .compress = sha512_compress,
  .initial_state = (u8 *)SHA384_STATE,
  .state_words = 8,
  .word_size = sizeof(u64),
};

const HashAlgorithm sha384_algorithm = {
  .name = "SHA2-384",
  .type = HASH_TYPE_MERKLE_DAMGARD,
  .config = &sha384_config,
  .digest_size = 48,
  .block_size = 128,
  .state_size = 64,
  .init = merkle_damgard_init,
  .update = merkle_damgard_update,
  .finalize = merkle_damgard_finalize,
  .reset = merkle_damgard_reset
};

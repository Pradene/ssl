#ifndef FT_SSL_H
#define FT_SSL_H

#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <stdint.h>
#include <stdbool.h>
#include <endian.h>

#include "libft.h"

#define ROTR(value, amount, bits) (((value) >> ((amount) % (bits))) | ((value) << ((bits) - ((amount) % (bits)))))
#define ROTL(value, amount, bits) (((value) << ((amount) % (bits))) | ((value) >> ((bits) - ((amount) % (bits)))))

#define ROTR32(val, amt) ROTR(val, amt, 32)
#define ROTL32(val, amt) ROTL(val, amt, 32)
#define ROTR64(val, amt) ROTR(val, amt, 64)
#define ROTL64(val, amt) ROTL(val, amt, 64)

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;
typedef __uint128_t u128;

typedef enum {
  HASH_TYPE_MERKLE_DAMGARD,
  HASH_TYPE_BLOCK_CIPHER,
  HASH_TYPE_SPONGE,
} HashType;

typedef struct HashAlgorithm HashAlgorithm;

typedef struct HashContext {
  HashAlgorithm *algorithm;
  u8            *state;        // Current hash state
  u8            *buffer;       // Input buffer for partial blocks
  u128          total_length;  // Total input length in bytes
  u32           buffer_length; // Current buffer length
} HashContext;

typedef struct HashAlgorithm {
  char      *name;
  HashType  type;
  void      *config;
  u32       digest_size;       // Output size in bytes
  u32       block_size;        // Block size in bytes
  u32       state_size;        // Size of algorithm-specific state in bytes

  // Function pointers for algorithm operations
  void  (*init)(HashContext *ctx);
  void  (*update)(HashContext *ctx, u8 *data, u128 len);
  void  (*finalize)(HashContext *ctx, u8 *digest);
  void  (*reset)(HashContext *ctx);
} HashAlgorithm;

typedef struct {
  u32   length_size;       // Size of length field in padding (bytes)
  u32   length_endian;     // Endianness of length field
  u8    *initial_state;    // Initial hash values
  u32   state_words;       // Number of words in state
  u32   word_size;         // Size of one state word

  void  (*compress)(u8 *_state, u8 *block);  // Compression function
} MerkleConfig;

typedef struct {
  u32   key_size;          // Key size in bytes
  u32   rounds;            // Number of rounds
  void  (*encrypt)(u8 *key, u8 *plaintext, u8 *ciphertext);
  void  (*key_schedule)(u8 *master_key, u8 *round_keys);
} BlockCipherConfig;

typedef struct {
  char  *name;
  char  *description;
  void  (*handler)(void);
} Option;

typedef struct {
  char            *name;
  HashAlgorithm   *algorithm;
} Command;

typedef enum {
  INPUT_STRING = 1,
  INPUT_FILE   = 2,
  INPUT_STDIN  = 3
} InputType;

// Global flags
extern bool print_stdin;
extern bool reverse;
extern bool string;
extern bool quiet;

// Function declarations
Command *parse_command(u32 argc, char *argv[]);
u32     parse_options(u32 argc, char *argv[]);

// Hash interface
void hash_string(char *string, HashAlgorithm *alg);
void hash_file(char *filename, HashAlgorithm *alg);
void hash_stdin(HashAlgorithm *alg);

// Generic hash operations
HashContext *hash_create(HashAlgorithm *algorithm);
void hash_destroy(HashContext *ctx);
void hash_update(HashContext *ctx, u8 *data, u128 len);
void hash_finalize(HashContext *ctx, u8 *digest);
void hash_reset(HashContext *ctx);

// Merkle-Damgård specific functions
void merkle_damgard_init(HashContext *ctx);
void merkle_damgard_update(HashContext *ctx, u8 *data, u128 len);
void merkle_damgard_finalize(HashContext *ctx, u8 *digest);
void merkle_damgard_reset(HashContext *ctx);

// Algorithm-specific compression functions
void md5_compress(u8 *_state, u8 *block);
void sha256_compress(u8 *_state, u8 *block);
void sha512_compress(u8 *_state, u8 *block);

// Utils
void output_digest(HashAlgorithm *algorithm, u8 *digest, char *input, InputType type);

// Algorithm instances
extern HashAlgorithm md5_algorithm;
extern HashAlgorithm sha224_algorithm;
extern HashAlgorithm sha256_algorithm;
extern HashAlgorithm sha384_algorithm;
extern HashAlgorithm sha512_algorithm;

#endif // FT_SSL_H
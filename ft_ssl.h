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
  const HashAlgorithm *algorithm;
  u8                  *state;        // Current hash state
  u8                  *buffer;       // Input buffer for partial blocks
  u128                total_length;  // Total input length in bytes
  u32                 buffer_length; // Current buffer length
} HashContext;

typedef struct HashAlgorithm {
  const char    *name;
  HashType      type;
  void          *config;
  u32           digest_size;       // Output size in bytes
  u32           block_size;        // Block size in bytes
  u32           state_size;        // Size of algorithm-specific state in bytes

  // Function pointers for algorithm operations
  void  (*init)(HashContext *ctx);
  void  (*update)(HashContext *ctx, const u8 *data, u128 len);
  void  (*finalize)(HashContext *ctx, u8 *digest);
  void  (*reset)(HashContext *ctx);
} HashAlgorithm;

typedef struct {
  u32   length_size;       // Size of length field in padding (bytes)
  u32   length_endian;     // Endianness of length field
  u8    *initial_state;    // Initial hash values
  u32   state_words;       // Number of words in state
  u32   word_size;         // Size of one state word

  void  (*compress)(u8 *_state, const u8 *block);  // Compression function
} MerkleConfig;

typedef struct {
  u32 key_size;          // Key size in bytes
  u32 rounds;            // Number of rounds
  void (*encrypt)(const u8 *key, const u8 *plaintext, u8 *ciphertext);
  void (*key_schedule)(const u8 *master_key, u8 *round_keys);
} BlockCipherConfig;

typedef struct {
  const char  *name;
  const char  *description;
  void        (*handler)(void);
} Option;

typedef struct {
  const char            *name;
  const HashAlgorithm   *algorithm;
} Command;

// Global flags
extern bool print_stdin;
extern bool reverse;
extern bool string;
extern bool quiet;

// Function declarations
Command *parse_command(u32 argc, char *argv[]);
u32     parse_options(u32 argc, char *argv[]);

// Hash interface
void hash_string(const char *string, const HashAlgorithm *alg);
void hash_file(const char *filename, const HashAlgorithm *alg);
void hash_stdin(const HashAlgorithm *alg);

// Generic hash operations
HashContext *hash_create(const HashAlgorithm *algorithm);
void hash_destroy(HashContext *ctx);
void hash_update(HashContext *ctx, const u8 *data, u128 len);
void hash_finalize(HashContext *ctx, u8 *digest);
void hash_reset(HashContext *ctx);

// Merkle-Damgård specific functions
void merkle_damgard_init(HashContext *ctx);
void merkle_damgard_update(HashContext *ctx, const u8 *data, u128 len);
void merkle_damgard_finalize(HashContext *ctx, u8 *digest);
void merkle_damgard_reset(HashContext *ctx);

// Algorithm-specific compression functions
void md5_compress(u8 *_state, const u8 *block);
void sha256_compress(u8 *_state, const u8 *block);
void sha512_compress(u8 *_state, const u8 *block);

// Utils
void print_digest(const u8 *digest, u32 size, const char *input, const char *algorithm_name);

// Algorithm instances
extern const HashAlgorithm md5_algorithm;
extern const HashAlgorithm sha224_algorithm;
extern const HashAlgorithm sha256_algorithm;
extern const HashAlgorithm sha384_algorithm;
extern const HashAlgorithm sha512_algorithm;

#endif // FT_SSL_H
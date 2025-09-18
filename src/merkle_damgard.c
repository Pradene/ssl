#include "ft_ssl.h"

void merkle_damgard_init(HashContext *ctx) {
  const MerkleConfig  *config = (MerkleConfig *)ctx->algorithm->config;
  
  // Copy initial state
  ft_memcpy(ctx->state, config->initial_state, config->state_words * config->word_size);
  
  ctx->total_length = 0;
  ctx->buffer_length = 0;
}

void merkle_damgard_update(HashContext *ctx, const u8 *data, u64 len) {
  const MerkleConfig  *config = (MerkleConfig *)ctx->algorithm->config;
  
  ctx->total_length += len;
  u64 remaining = len;
  u64 offset = 0;

  // If we have buffered data, try to complete a block
  if (ctx->buffer_length > 0) {
    u32 needed = ctx->algorithm->block_size - ctx->buffer_length;
    u32 to_copy = (remaining < needed) ? remaining : needed;
    
    ft_memcpy(ctx->buffer + ctx->buffer_length, data, to_copy);
    ctx->buffer_length += to_copy;
    offset += to_copy;
    remaining -= to_copy;

    if (ctx->buffer_length == ctx->algorithm->block_size) {
      config->compress(ctx->state, ctx->buffer);
      ctx->buffer_length = 0;
    }
  }

  // Process complete blocks
  while (remaining >= ctx->algorithm->block_size) {
    config->compress(ctx->state, data + offset);
    offset += ctx->algorithm->block_size;
    remaining -= ctx->algorithm->block_size;
  }

  // Buffer remaining data
  if (remaining > 0) {
    ft_memcpy(ctx->buffer + ctx->buffer_length, data + offset, remaining);
    ctx->buffer_length += remaining;
  }
}

void merkle_damgard_finalize(HashContext *ctx, u8 *digest) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;

  u64 total_bits = ctx->total_length * 8;
  u64 message_length = ctx->buffer_length;
  
  // Add padding bit
  ctx->buffer[message_length++] = 0x80;
  
  // Calculate required padding
  u64 padding_needed = ctx->algorithm->block_size - config->length_size;
  if (message_length > padding_needed) {
    // Need an additional block
    ft_memset(ctx->buffer + message_length, 0, ctx->algorithm->block_size - message_length);
    config->compress(ctx->state, ctx->buffer);
    message_length = 0;
  }
  
  // Pad with zeros
  ft_memset(ctx->buffer + message_length, 0, padding_needed - message_length);
  
  // Append length
  if (config->length_size == 8) {
    u64 length_be = to_endian64(total_bits, config->length_endian);
    ft_memcpy(ctx->buffer + padding_needed, &length_be, 8);
  } else if (config->length_size == 16) {
    // For SHA-512 style: 128-bit length (high 64 bits = 0, low 64 bits = length)
    u64 length_high = 0;
    u64 length_low = to_endian64(total_bits, config->length_endian);
    if (config->length_endian == __ORDER_BIG_ENDIAN__) {
      ft_memcpy(ctx->buffer + padding_needed, &length_high, 8);
      ft_memcpy(ctx->buffer + padding_needed + 8, &length_low, 8);
    } else {
      ft_memcpy(ctx->buffer + padding_needed, &length_low, 8);
      ft_memcpy(ctx->buffer + padding_needed + 8, &length_high, 8);
    }
  }
  
  // Final compression
  config->compress(ctx->state, ctx->buffer);
  
  // Output digest - handle different word sizes
  if (config->word_size == 4) {
    // 32-bit words (MD5, SHA-1, SHA-256)
    if (config->length_endian == __ORDER_LITTLE_ENDIAN__) {
      // MD5 style - little endian output
      for (u32 i = 0; i < config->state_words; ++i) {
        u32 word = ((u32 *)ctx->state)[i];
        digest[i*4 + 0] = (word >>  0) & 0xFF;
        digest[i*4 + 1] = (word >>  8) & 0xFF;
        digest[i*4 + 2] = (word >> 16) & 0xFF;
        digest[i*4 + 3] = (word >> 24) & 0xFF;
      }
    } else {
      // SHA-256 style - big endian output
      for (u32 i = 0; i < config->state_words; ++i) {
        u32 word = ((u32 *)ctx->state)[i];
        digest[i*4 + 0] = (word >> 24) & 0xFF;
        digest[i*4 + 1] = (word >> 16) & 0xFF;
        digest[i*4 + 2] = (word >>  8) & 0xFF;
        digest[i*4 + 3] = (word >>  0) & 0xFF;
      }
    }
  } else if (config->word_size == 8) {
    // 64-bit words (SHA-512, SHA-384)
    if (config->length_endian == __ORDER_LITTLE_ENDIAN__) {
      // Little endian output (hypothetical)
      for (u32 i = 0; i < config->state_words; ++i) {
        u64 word = ((u64 *)ctx->state)[i];
        digest[i*8 + 0] = (word >>  0) & 0xFF;
        digest[i*8 + 1] = (word >>  8) & 0xFF;
        digest[i*8 + 2] = (word >> 16) & 0xFF;
        digest[i*8 + 3] = (word >> 24) & 0xFF;
        digest[i*8 + 4] = (word >> 32) & 0xFF;
        digest[i*8 + 5] = (word >> 40) & 0xFF;
        digest[i*8 + 6] = (word >> 48) & 0xFF;
        digest[i*8 + 7] = (word >> 56) & 0xFF;
      }
    } else {
      // SHA-512 style - big endian output
      for (u32 i = 0; i < config->state_words; ++i) {
        u64 word = ((u64 *)ctx->state)[i];
        digest[i*8 + 0] = (word >> 56) & 0xFF;
        digest[i*8 + 1] = (word >> 48) & 0xFF;
        digest[i*8 + 2] = (word >> 40) & 0xFF;
        digest[i*8 + 3] = (word >> 32) & 0xFF;
        digest[i*8 + 4] = (word >> 24) & 0xFF;
        digest[i*8 + 5] = (word >> 16) & 0xFF;
        digest[i*8 + 6] = (word >>  8) & 0xFF;
        digest[i*8 + 7] = (word >>  0) & 0xFF;
      }
    }
  }
}

void merkle_damgard_reset(HashContext *ctx) {
  merkle_damgard_init(ctx);
}

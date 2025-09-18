#include "ft_ssl.h"

// Helper function to append length based on size
static void append_message_length(
  u8 *buffer,
  u64 offset,
  u64 total_bits, 
  u32 length_size,
  u32 endian
) {
  if (length_size == 8) {
    u64 length = to_endian64(total_bits, endian);
    ft_memcpy(buffer + offset, &length, 8);
  } else if (length_size == 16) {
    u64 length_high = to_endian64(0, endian);  // High 64 bits are 0
    u64 length_low = to_endian64(total_bits, endian);
    
    if (endian == __ORDER_BIG_ENDIAN__) {
      ft_memcpy(buffer + offset, &length_high, 8);
      ft_memcpy(buffer + offset + 8, &length_low, 8);
    } else {
      ft_memcpy(buffer + offset, &length_low, 8);
      ft_memcpy(buffer + offset + 8, &length_high, 8);
    }
  }
}

// Helper function to write a word to digest in the correct byte order
static void write_word_to_digest(
  u8 *digest,
  u32 word_index,
  u64 word, 
  u32 word_size,
  u32 endian
) {
  u32 byte_offset = word_index * word_size;
  
  for (u32 i = 0; i < word_size; i++) {
    if (endian == __ORDER_LITTLE_ENDIAN__) {
      digest[byte_offset + i] = (word >> (i * 8)) & 0xFF;
    } else {
      digest[byte_offset + i] = (word >> ((word_size - 1 - i) * 8)) & 0xFF;
    }
  }
}

// Helper function to output the digest
static void output_digest(HashContext *ctx, u8 *digest) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;
  
  for (u32 i = 0; i < config->state_words; i++) {
    u64 word;
    if (config->word_size == 4) {
      word = ((u32 *)ctx->state)[i];
    } else if (config->word_size == 8) {
      word = ((u64 *)ctx->state)[i];
    } else {
      // Handle other word sizes if needed in the future
      word = 0;
    }
    
    write_word_to_digest(digest, i, word, config->word_size, config->length_endian);
  }
}

// Helper function to apply padding
static void apply_padding(HashContext *ctx, u64 total_bits) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;
  u64 message_length = ctx->buffer_length;
  
  // Add padding bit
  ctx->buffer[message_length++] = 0x80;
  
  // Calculate where length field starts
  u64 length_field_start = ctx->algorithm->block_size - config->length_size;
  
  // Check if we need an additional block
  if (message_length > length_field_start) {
    // Pad current block and compress
    ft_memset(ctx->buffer + message_length, 0, ctx->algorithm->block_size - message_length);
    config->compress(ctx->state, ctx->buffer);
    message_length = 0;
  }
  
  // Pad with zeros up to length field
  ft_memset(ctx->buffer + message_length, 0, length_field_start - message_length);
  
  // Append length
  append_message_length(
    ctx->buffer,
    length_field_start,
    total_bits, 
    config->length_size,
    config->length_endian
  );
}

void merkle_damgard_init(HashContext *ctx) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;
  
  // Copy initial state
  ft_memcpy(ctx->state, config->initial_state, config->state_words * config->word_size);
  
  ctx->total_length = 0;
  ctx->buffer_length = 0;
}

void merkle_damgard_update(HashContext *ctx, const u8 *data, u64 len) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;
  
  ctx->total_length += len;
  u64 remaining = len;
  u64 offset = 0;

  // Complete partial block if exists
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

  // Process complete blocks directly
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
  
  // Apply Merkle-Damgård padding
  apply_padding(ctx, total_bits);
  
  // Final compression
  config->compress(ctx->state, ctx->buffer);
  
  // Output digest in correct format
  output_digest(ctx, digest);
}

void merkle_damgard_reset(HashContext *ctx) {
  merkle_damgard_init(ctx);
}

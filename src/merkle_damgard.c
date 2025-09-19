#include "ft_ssl.h"

void merkle_damgard_init(HashContext *ctx) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;
  
  ft_memcpy(ctx->state, config->initial_state, config->state_words * config->word_size);
  
  ctx->total_length = 0;
  ctx->buffer_length = 0;
}

void merkle_damgard_update(HashContext *ctx, const u8 *data, u128 len) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;
  
  ctx->total_length += len * 8;
  u128 remaining = len;
  u128 offset = 0;

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

  while (remaining >= ctx->algorithm->block_size) {
    config->compress(ctx->state, data + offset);
    offset += ctx->algorithm->block_size;
    remaining -= ctx->algorithm->block_size;
  }

  if (remaining > 0) {
    ft_memcpy(ctx->buffer + ctx->buffer_length, data + offset, remaining);
    ctx->buffer_length += remaining;
  }
}

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

static void output_digest(HashContext *ctx, u8 *digest) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;
  
  if (config->word_size == 1) {
    ft_memcpy(digest, ctx->state, config->state_words);
  } else {
    for (u32 i = 0; i < config->state_words; i++) {
      u64 word = 0;
      
      u8 *state_bytes = (u8 *)ctx->state;
      for (u32 j = 0; j < config->word_size && j < 8; j++) {
        word |= ((u64)state_bytes[i * config->word_size + j]) << (j * 8);
      }

      write_word_to_digest(digest, i, word, config->word_size, config->length_endian);
    }
  }
}

static void append_message_length(
  u8 *buffer,
  u128 total_bits,
  u32 length_size,
  u32 endian
) {
  for (u32 i = 0; i < length_size; i++) {
    u32 byte_index;
    if (endian == __ORDER_BIG_ENDIAN__) {
      byte_index = length_size - 1 - i;
    } else {
      byte_index = i;
    }
    buffer[byte_index] = (total_bits >> (i * 8)) & 0xFF;
  }
}

static void apply_padding(HashContext *ctx, u128 total_bits) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;

  ft_memset(ctx->buffer + ctx->buffer_length, 0x80, 1);
  ctx->buffer_length += 1;

  u64 length_field_start = ctx->algorithm->block_size - config->length_size;

  if (ctx->buffer_length > length_field_start) {
    ft_memset(ctx->buffer + ctx->buffer_length, 0, ctx->algorithm->block_size - ctx->buffer_length);
    config->compress(ctx->state, ctx->buffer);
    ctx->buffer_length = 0;
  }

  ft_memset(ctx->buffer + ctx->buffer_length, 0, length_field_start - ctx->buffer_length);
  
  append_message_length(
    ctx->buffer + length_field_start,
    total_bits, 
    config->length_size,
    config->length_endian
  );
}

void merkle_damgard_finalize(HashContext *ctx, u8 *digest) {
  const MerkleConfig *config = (MerkleConfig *)ctx->algorithm->config;

  apply_padding(ctx, ctx->total_length);
  config->compress(ctx->state, ctx->buffer);

  output_digest(ctx, digest);
}

void merkle_damgard_reset(HashContext *ctx) {
  merkle_damgard_init(ctx);
}
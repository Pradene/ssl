#include "ft_ssl.h"

HashContext *hash_create(const HashAlgorithm *algorithm) {
  HashContext *ctx = malloc(sizeof(HashContext));
  if (!ctx) {
    return (NULL);
  }

  ctx->algorithm = algorithm;
  ctx->state = malloc(algorithm->state_size);
  ctx->buffer = malloc(algorithm->block_size);
  ctx->total_length = 0;
  ctx->buffer_length = 0;

  if (!ctx->state || !ctx->buffer) {
    hash_destroy(ctx);
    return (NULL);
  }

  ctx->algorithm->init(ctx);
  return (ctx);
}

void hash_destroy(HashContext *ctx) {
  if (ctx) {
    free(ctx->state);
    free(ctx->buffer);
    free(ctx);
  }
}

void hash_update(HashContext *ctx, const u8 *data, u128 len) {
  ctx->algorithm->update(ctx, data, len);
}

void hash_finalize(HashContext *ctx, u8 *digest) {
  ctx->algorithm->finalize(ctx, digest);
}

void hash_reset(HashContext *ctx) {
  ctx->algorithm->reset(ctx);
}

#include "ft_ssl.h"

void hash_string(const char *string, const HashAlgorithm *alg) {
  HashContext *ctx = hash_create(alg);
  if (!ctx) {
    ft_fprintf(stderr, "Error: Failed to create hash context\n");
    return ;
  }

  hash_update(ctx, (const u8 *)string, ft_strlen(string));
  
  u8 digest[64] = {0};
  hash_finalize(ctx, digest);
  print_digest(digest, alg->digest_size, string, alg->name);
  
  hash_destroy(ctx);
}

void hash_file(const char *filename, const HashAlgorithm *alg) {
  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    ft_fprintf(stderr, "Error: Cannot open file %s\n", filename);
    return ;
  }

  HashContext *ctx = hash_create(alg);
  if (!ctx) {
    ft_fprintf(stderr, "Error: Failed to create hash context\n");
    close(fd);
    return ;
  }

  u8      buffer[4096] = {0};
  ssize_t bytes_read;
  while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
    hash_update(ctx, buffer, bytes_read);
  }
  
  u8 digest[64] = {0};
  hash_finalize(ctx, digest);
  print_digest(digest, alg->digest_size, filename, alg->name);
  
  hash_destroy(ctx);
  close(fd);
}

void hash_stdin(const HashAlgorithm *alg) {
  HashContext *ctx = hash_create(alg);
  if (!ctx) {
    ft_fprintf(stderr, "Error: Failed to create hash context\n");
    return ;
  }

  u8      buffer[4096] = {0};
  ssize_t bytes_read;
  while ((bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
    hash_update(ctx, buffer, bytes_read);
  }
  
  u8 digest[64] = {0};
  hash_finalize(ctx, digest);
  print_digest(digest, alg->digest_size, NULL, alg->name);
  
  hash_destroy(ctx);
}
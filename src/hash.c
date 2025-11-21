// hash.c
#include "ft_ssl.h"

void hash_string(const char *string, const HashAlgorithm *alg) {
  HashContext *ctx = hash_create(alg);
  if (!ctx) {
    ft_fprintf(stderr, "ft_ssl: error: Failed to create hash context\n");
    return ;
  }

  hash_update(ctx, (const u8 *)string, ft_strlen(string));
  
  u8 digest[64] = {0};
  hash_finalize(ctx, digest);
  output_digest(digest, alg->digest_size, string, alg->name, 1);  // 1 = string
  
  hash_destroy(ctx);
}

void hash_file(const char *filename, const HashAlgorithm *alg) {
  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    ft_fprintf(stderr, "ft_ssl: error: Failed to open '%s'\n", filename);
    return ;
  }

  HashContext *ctx = hash_create(alg);
  if (!ctx) {
    ft_fprintf(stderr, "ft_ssl: error: Failed to create hash context\n");
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
  output_digest(digest, alg->digest_size, filename, alg->name, 2);  // 2 = file
  
  hash_destroy(ctx);
  close(fd);
}

void hash_stdin(const HashAlgorithm *alg) {
  HashContext *ctx = hash_create(alg);
  if (!ctx) {
    ft_fprintf(stderr, "ft_ssl: error: Failed to create hash context\n");
    return ;
  }

  u8      buffer[4096] = {0};
  ssize_t bytes_read;
  char    *stdin_copy = NULL;
  size_t  stdin_len = 0;

  // Read all stdin
  while ((bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
    hash_update(ctx, buffer, bytes_read);

    // Store stdin content for later display
    char *temp = realloc(stdin_copy, stdin_len + bytes_read);
    if (temp) {
      ft_memcpy(temp + stdin_len, buffer, bytes_read);
      stdin_copy = temp;
      stdin_len += bytes_read;
    }
  }

  u8 digest[64] = {0};
  hash_finalize(ctx, digest);

  // Strip trailing newline for display (but it was hashed)
  if (stdin_copy && stdin_len > 0 && stdin_copy[stdin_len - 1] == '\n') {
    stdin_copy[stdin_len - 1] = '\0';
    output_digest(digest, alg->digest_size, stdin_copy, alg->name, 3);  // 3 = stdin
  } else if (stdin_copy) {
    output_digest(digest, alg->digest_size, stdin_copy, alg->name, 3);
  } else {
    output_digest(digest, alg->digest_size, NULL, alg->name, 0);  // no input
  }
  
  if (stdin_copy) free(stdin_copy);
  hash_destroy(ctx);
}

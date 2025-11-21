#include "ft_ssl.h"

void hash_string(char *string, HashAlgorithm *algorithm) {
  HashContext *ctx = hash_create(algorithm);
  if (!ctx) {
    ft_fprintf(stderr, "ft_ssl: error: Failed to create hash context\n");
    return ;
  }

  hash_update(ctx, ( u8 *)string, ft_strlen(string));
  
  u8 digest[64] = {0};
  hash_finalize(ctx, digest);
  output_digest(algorithm, digest, string, INPUT_STRING);
  
  hash_destroy(ctx);
}

void hash_file(char *filename, HashAlgorithm *algorithm) {
  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    ft_fprintf(stderr, "ft_ssl: error: Failed to open '%s'\n", filename);
    return ;
  }

  HashContext *ctx = hash_create(algorithm);
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
  output_digest(algorithm, digest, filename, INPUT_FILE);
  
  hash_destroy(ctx);
  close(fd);
}

void hash_stdin(HashAlgorithm *algorithm) {
  HashContext *ctx = hash_create(algorithm);
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
  }

  output_digest(algorithm, digest, stdin_copy, INPUT_STDIN);
  
  if (stdin_copy) {
    free(stdin_copy);
  }
  
  hash_destroy(ctx);
}

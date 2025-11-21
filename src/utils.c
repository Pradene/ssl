#include "ft_ssl.h"

static void print_digest(HashAlgorithm *algorithm, u8* digest) {
  for (u64 i = 0; i < algorithm->digest_size; ++i) {
    ft_printf("%02x", digest[i]);
  }
}

static void print_input_label(char *input, InputType type) {
  if (type == INPUT_STRING) {
    ft_printf(" \"%s\"", input);
  } else if (type == INPUT_FILE) {
    ft_printf(" %s", input);
  } else {
    if (print_stdin && input && input[0]) {
      ft_printf(" (\"%s\")", input);
    } else {
      ft_printf(" (stdin)");
    }
  }
}

static void output_reverse(HashAlgorithm *algorithm, u8 *digest, char *input, InputType type) {
  print_digest(algorithm, digest);
  print_input_label(input, type);
  ft_printf("\n");
}

static void output_normal(HashAlgorithm *algorithm, u8 *digest, char *input,  InputType type) {
  if (type == INPUT_STRING) {
    ft_printf("%s(\"%s\")= ", algorithm->name, input);
  } else if (type == INPUT_FILE) {
    ft_printf("%s(%s)= ", algorithm->name, input);
  } else {
    if (print_stdin && input && input[0]) {
      ft_printf("(\"%s\")= ", input);
    } else {
      ft_printf("(stdin)= ");
    }
  }
  print_digest(algorithm, digest);
  ft_printf("\n");
}

static void output_quiet(HashAlgorithm *algorithm,  u8 *digest, char *input, InputType type) {
  if (type == INPUT_STDIN && print_stdin && input && input[0]) {
    ft_printf("%s\n", input);
  }
  print_digest(algorithm, digest);
  ft_printf("\n");
}

void output_digest(HashAlgorithm *algorithm, u8 *digest, char *input, InputType type) {
  if (quiet) {
    output_quiet(algorithm, digest, input, type);
  } else if (reverse) {
    output_reverse(algorithm, digest, input, type);
  } else {
    output_normal(algorithm, digest, input, type);
  }
}

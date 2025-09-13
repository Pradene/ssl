#include "ft_ssl.h"

void print_byte_binary(uint8_t byte) {
    for (int i = 7; i >= 0; --i) {
        printf("%d", (byte >> i) & 1);
    }
}

void print_buffer_hex_binary(char *buffer, uint64_t size) {
    printf("Buffer (Hex + Binary):\n");
    printf("Byte | Hex | Binary   | ASCII\n");
    printf("-----|-----|----------|------\n");

    for (uint64_t i = 0; i < size; i++) {
        uint8_t byte = (uint8_t)buffer[i];
        printf("%4lu | %02X  | ", i, byte);
        print_byte_binary(byte);
        printf(" | %c\n", (byte >= 32 && byte < 127) ? byte : '.');

        // Add separator every 16 bytes
        if ((i + 1) % 16 == 0 && i + 1 < size) {
            printf("-----|-----|----------|------\n");
        }
    }
    printf("-----|-----|----------|------\n");
}


#ifndef BINARY_H
#define BINARY_H

#include <stddef.h>

typedef struct {
    const char *path;
    unsigned char *data;
    size_t size;
} Binary;

int load_binary(Binary *bin, const char *path);
void free_binary(Binary *bin);
int read_bytes(const Binary *bin, size_t offset, void *out, size_t count);
const char *read_string(const Binary *bin, size_t offset);

#endif

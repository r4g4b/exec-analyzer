#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "binary.h"

int load_binary(Binary *bin, const char *path) {
    FILE *file;
    long size;

    bin->path = path;
    bin->data = NULL;
    bin->size = 0;

    file = fopen(path, "rb");
    if (file == NULL) return 0;

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (size <= 0) {
        fclose(file);
        return 0;
    }

    bin->data = malloc((size_t)size);
    if (bin->data == NULL) {
        fclose(file);
        return 0;
    }

    if (fread(bin->data, 1, (size_t)size, file) != (size_t)size) {
        free(bin->data);
        bin->data = NULL;
        fclose(file);
        return 0;
    }

    bin->size = (size_t)size;
    fclose(file);
    return 1;
}

void free_binary(Binary *bin) {
    free(bin->data);
    bin->data = NULL;
    bin->size = 0;
}

int read_bytes(const Binary *bin, size_t offset, void *out, size_t count) {
    if (offset > bin->size || count > bin->size - offset) return 0;
    memcpy(out, bin->data + offset, count);
    return 1;
}

const char *read_string(const Binary *bin, size_t offset) {
    for (size_t i = offset; i < bin->size; i++) {
        if (bin->data[i] == '\0') return (const char *)(bin->data + offset);
    }
    return "<invalid>";
}

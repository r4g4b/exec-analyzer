#ifndef OPTIONS_H
#define OPTIONS_H

typedef struct {
    int all;
    int help;
    int file_header;
    int sections;
    int segments;
    int libraries;
    int imports;
    int exports;
    int dos_header;
    int nt_header;
    int optional_header;
    int data_directory;
    int relocations;
} Options;

int parse_options(Options *opts, const char **path, int argc, char **argv);
int has_any_option(const Options *opts);
void print_help(const char *program);

#endif

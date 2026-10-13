#include <stdio.h>
#include <string.h>
#include "options.h"
#include "output.h"

int parse_options(Options *opts, const char **path, int argc, char **argv) {
    memset(opts, 0, sizeof(Options));
    *path = NULL;

    for (int i = 1; i < argc; i++) {
        char *flag = argv[i];

        if (flag[0] != '-') {
            if (*path != NULL) {
                printf("Unknown argument: %s\n", flag);
                return 0;
            }
            *path = flag;
            continue;
        }

        flag++;
        while (*flag) {
            switch (*flag) {
                case 'a': opts->all = 1; break;
                case 'h': opts->help = 1; break;
                case 'f': opts->file_header = 1; break;
                case 's': opts->sections = 1; break;
                case 'p': opts->segments = 1; break;
                case 'i': opts->libraries = 1; break;
                case 'I': opts->imports = 1; break;
                case 'e': opts->exports = 1; break;
                case 'd': opts->dos_header = 1; break;
                case 'n': opts->nt_header = 1; break;
                case 'o': opts->optional_header = 1; break;
                case 'D': opts->data_directory = 1; break;
                case 'r': opts->relocations = 1; break;
                default:
                    printf("Unknown flag: -%c\n", *flag);
                    return 0;
            }
            flag++;
        }
    }
    return 1;
}

int has_any_option(const Options *opts) {
    return opts->all || opts->file_header || opts->sections || opts->segments ||
           opts->libraries || opts->imports || opts->exports || opts->dos_header ||
           opts->nt_header || opts->optional_header || opts->data_directory ||
           opts->relocations;
}

void print_help(const char *program) {
    printf("Usage: %s <file> [flags]\n\n", program);
    echo("Flags for all formats:\n", "blue");
    echo("\t-a  Show everything\n", "green");
    echo("\t-f  File header\n", "green");
    echo("\t-s  Sections\n", "green");
    echo("\t-i  Imported libraries\n", "green");
    echo("\t-I  Imported functions\n", "green");
    echo("\t-e  Exported functions\n", "green");
    echo("\t-h  Show this help\n", "green");
    echo("ELF and Mach-O only:\n", "blue");
    echo("\t-p  Program headers (ELF) / Load commands and segments (Mach-O)\n", "green");
    echo("PE only:\n", "blue");
    echo("\t-d  DOS header\n", "green");
    echo("\t-n  NT header\n", "green");
    echo("\t-o  Optional header\n", "green");
    echo("\t-D  Data directories\n", "green");
    echo("\t-r  Base relocations\n", "green");
}

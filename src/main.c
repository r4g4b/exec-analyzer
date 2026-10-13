#include <stdio.h>
#include "binary.h"
#include "options.h"
#include "output.h"
#include "pe.h"
#include "elf.h"
#include "macho.h"

static void print_banner(const Binary *bin, const char *format) {
    echo("\n=====================================================================\n", "cyan");
    echo("                            Key Information                          \n", "cyan");
    echo("=====================================================================\n", "cyan");
    printf("\tFile:   %s\n", bin->path);
    printf("\tFormat: %s\n", format);
    printf("\tSize:   %lu bytes\n", (unsigned long)bin->size);
}

int main(int argc, char **argv) {
    Options opts;
    Binary bin;
    const char *path;

    init_colors();

    if (!parse_options(&opts, &path, argc, argv)) {
        print_help(argv[0]);
        return 1;
    }
    if (opts.help) {
        print_help(argv[0]);
        return 0;
    }
    if (path == NULL) {
        echo("No file specified\n", "red");
        print_help(argv[0]);
        return 1;
    }
    if (!has_any_option(&opts)) {
        echo("No flag specified\n", "yellow");
        print_help(argv[0]);
        return 1;
    }
    if (!load_binary(&bin, path)) {
        echo("[!] Could not open the file: ", "red");
        printf("%s\n", path);
        return 1;
    }

    if (is_pe(&bin)) {
        print_banner(&bin, "PE (Windows)");
        analyze_pe(&bin, &opts);
    } else if (is_elf(&bin)) {
        print_banner(&bin, "ELF (Linux / Unix)");
        analyze_elf(&bin, &opts);
    } else if (is_macho(&bin)) {
        print_banner(&bin, "Mach-O (macOS / iOS)");
        analyze_macho(&bin, &opts);
    } else {
        echo("[!] Unknown file format, only PE, ELF and Mach-O are supported\n", "red");
        free_binary(&bin);
        return 1;
    }

    free_binary(&bin);
    return 0;
}

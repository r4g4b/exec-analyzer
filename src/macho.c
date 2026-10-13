#include <stdio.h>
#include <string.h>
#include "macho.h"
#include "output.h"

#define MAX_LIBRARIES 256

static uint32_t swap32(uint32_t value) {
    return ((value & 0x000000FF) << 24) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0xFF000000) >> 24);
}

static const char *cpu_name(int32_t cputype, int32_t cpusubtype) {
    switch (cputype) {
        case 7: return "x86";
        case 0x01000007: return "x86_64";
        case 12: return "ARM";
        case 0x0100000C: return (cpusubtype & 0xFF) == 2 ? "ARM64e" : "ARM64";
        case 0x0200000C: return "ARM64_32";
        case 18: return "PowerPC";
        case 0x01000012: return "PowerPC 64";
        default: return "Unknown";
    }
}

static const char *file_type_name(uint32_t type) {
    switch (type) {
        case 1: return "Object file";
        case 2: return "Executable";
        case 3: return "Fixed VM shared library";
        case 4: return "Core dump";
        case 5: return "Preloaded executable";
        case 6: return "Dynamic library (dylib)";
        case 7: return "Dynamic linker";
        case 8: return "Bundle";
        case 9: return "Dylib stub";
        case 10: return "Debug symbols (dSYM)";
        case 11: return "Kernel extension";
        default: return "Unknown";
    }
}

static const char *platform_name(uint32_t platform) {
    switch (platform) {
        case 1: return "macOS";
        case 2: return "iOS";
        case 3: return "tvOS";
        case 4: return "watchOS";
        case 6: return "Mac Catalyst";
        case 7: return "iOS Simulator";
        case 11: return "visionOS";
        default: return "Unknown";
    }
}

static const char *command_name(uint32_t cmd) {
    switch (cmd) {
        case 0x1: return "LC_SEGMENT";
        case 0x2: return "LC_SYMTAB";
        case 0x4: return "LC_THREAD";
        case 0x5: return "LC_UNIXTHREAD";
        case 0xB: return "LC_DYSYMTAB";
        case 0xC: return "LC_LOAD_DYLIB";
        case 0xD: return "LC_ID_DYLIB";
        case 0xE: return "LC_LOAD_DYLINKER";
        case 0xF: return "LC_ID_DYLINKER";
        case 0x19: return "LC_SEGMENT_64";
        case 0x1B: return "LC_UUID";
        case 0x1D: return "LC_CODE_SIGNATURE";
        case 0x1E: return "LC_SEGMENT_SPLIT_INFO";
        case 0x20: return "LC_LAZY_LOAD_DYLIB";
        case 0x21: return "LC_ENCRYPTION_INFO";
        case 0x22: return "LC_DYLD_INFO";
        case 0x24: return "LC_VERSION_MIN_MACOSX";
        case 0x25: return "LC_VERSION_MIN_IPHONEOS";
        case 0x26: return "LC_FUNCTION_STARTS";
        case 0x27: return "LC_DYLD_ENVIRONMENT";
        case 0x29: return "LC_DATA_IN_CODE";
        case 0x2A: return "LC_SOURCE_VERSION";
        case 0x2B: return "LC_DYLIB_CODE_SIGN_DRS";
        case 0x2C: return "LC_ENCRYPTION_INFO_64";
        case 0x2D: return "LC_LINKER_OPTION";
        case 0x32: return "LC_BUILD_VERSION";
        case 0x80000018: return "LC_LOAD_WEAK_DYLIB";
        case 0x8000001C: return "LC_RPATH";
        case 0x8000001F: return "LC_REEXPORT_DYLIB";
        case 0x80000022: return "LC_DYLD_INFO_ONLY";
        case 0x80000023: return "LC_LOAD_UPWARD_DYLIB";
        case 0x80000028: return "LC_MAIN";
        case 0x80000033: return "LC_DYLD_EXPORTS_TRIE";
        case 0x80000034: return "LC_DYLD_CHAINED_FIXUPS";
        default: return "UNKNOWN";
    }
}

static int is_dylib_command(uint32_t cmd) {
    return cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || cmd == LC_REEXPORT_DYLIB ||
           cmd == LC_LAZY_LOAD_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB;
}

static void protection_string(int32_t prot, char *out) {
    strcpy(out, "---");
    if (prot & 1) out[0] = 'R';
    if (prot & 2) out[1] = 'W';
    if (prot & 4) out[2] = 'X';
}

static void print_version(uint32_t version) {
    printf("%u.%u.%u", version >> 16, (version >> 8) & 0xFF, version & 0xFF);
}

int is_macho(const Binary *bin) {
    uint32_t magic;
    FatHeader fat;

    if (!read_bytes(bin, 0, &magic, sizeof(magic))) return 0;
    if (magic == MACHO_MAGIC_32 || magic == MACHO_MAGIC_64 ||
        magic == MACHO_CIGAM_32 || magic == MACHO_CIGAM_64) {
        return 1;
    }
    if (magic == MACHO_FAT_CIGAM && read_bytes(bin, 0, &fat, sizeof(fat))) {
        uint32_t count = swap32(fat.nfat_arch);
        return count > 0 && count < 20;
    }
    return 0;
}

static size_t first_command(const MachOFile *m) {
    return m->base + (m->is_64 ? sizeof(MachHeader) : sizeof(MachHeader) - 4);
}

static int read_segment(const MachOFile *m, size_t offset, SegmentCommand64 *out) {
    SegmentCommand32 s;

    if (m->is_64) return read_bytes(m->bin, offset, out, sizeof(SegmentCommand64));
    if (!read_bytes(m->bin, offset, &s, sizeof(s))) return 0;

    out->cmd = s.cmd;
    out->cmdsize = s.cmdsize;
    memcpy(out->segname, s.segname, 16);
    out->vmaddr = s.vmaddr;
    out->vmsize = s.vmsize;
    out->fileoff = s.fileoff;
    out->filesize = s.filesize;
    out->maxprot = s.maxprot;
    out->initprot = s.initprot;
    out->nsects = s.nsects;
    out->flags = s.flags;
    return 1;
}

static int read_section(const MachOFile *m, size_t offset, MachSection64 *out) {
    MachSection32 s;

    if (m->is_64) return read_bytes(m->bin, offset, out, sizeof(MachSection64));
    if (!read_bytes(m->bin, offset, &s, sizeof(s))) return 0;

    memset(out, 0, sizeof(MachSection64));
    memcpy(out->sectname, s.sectname, 16);
    memcpy(out->segname, s.segname, 16);
    out->addr = s.addr;
    out->size = s.size;
    out->offset = s.offset;
    out->align = s.align;
    out->flags = s.flags;
    return 1;
}

static int read_symbol(const MachOFile *m, size_t offset, Nlist64 *out) {
    Nlist32 n;

    if (m->is_64) return read_bytes(m->bin, offset, out, sizeof(Nlist64));
    if (!read_bytes(m->bin, offset, &n, sizeof(n))) return 0;

    out->n_strx = n.n_strx;
    out->n_type = n.n_type;
    out->n_sect = n.n_sect;
    out->n_desc = n.n_desc;
    out->n_value = n.n_value;
    return 1;
}

static void print_header(const MachOFile *m) {
    const MachHeader *h = &m->header;
    size_t offset = first_command(m);
    uint32_t f = h->flags;

    print_title("Mach-O Header");
    printf("\tMagic: 0x%08X (%s)\n", h->magic, m->is_64 ? "64-bit" : "32-bit");
    printf("\tArch (CPU): %s\n", cpu_name(h->cputype, h->cpusubtype));
    printf("\tFile Type: %s\n", file_type_name(h->filetype));
    printf("\tNumber of Load Commands: %u\n", h->ncmds);
    printf("\tSize of Load Commands: %u Bytes\n", h->sizeofcmds);
    printf("\tFlags: 0x%08X\n", f);
    if (f & 0x1) printf("\t  - No Undefined References\n");
    if (f & 0x4) printf("\t  - Dynamically Linked\n");
    if (f & 0x80) printf("\t  - Two Level Namespace\n");
    if (f & 0x8000) printf("\t  - Has Weak Definitions\n");
    if (f & 0x20000) echo("\t  - Allows Stack Execution\n", "red");
    if (f & 0x200000) printf("\t  - PIE (ASLR)\n");
    if (f & 0x1000000) printf("\t  - No Heap Execution\n");

    for (uint32_t i = 0; i < h->ncmds; i++) {
        LoadCommand lc;
        if (!read_bytes(m->bin, offset, &lc, sizeof(lc)) || lc.cmdsize < sizeof(lc)) break;

        if (lc.cmd == LC_MAIN) {
            EntryPointCommand entry;
            if (read_bytes(m->bin, offset, &entry, sizeof(entry))) {
                echo("\tEntry Point (file offset): ", "green");
                printf("0x%llX\n", (unsigned long long)entry.entryoff);
            }
        } else if (lc.cmd == LC_UUID) {
            UuidCommand uuid;
            if (read_bytes(m->bin, offset, &uuid, sizeof(uuid))) {
                printf("\tUUID: ");
                for (int j = 0; j < 16; j++) {
                    printf("%02X", uuid.uuid[j]);
                    if (j == 3 || j == 5 || j == 7 || j == 9) printf("-");
                }
                printf("\n");
            }
        } else if (lc.cmd == LC_BUILD_VERSION) {
            BuildVersionCommand build;
            if (read_bytes(m->bin, offset, &build, sizeof(build))) {
                printf("\tPlatform: %s\n", platform_name(build.platform));
                printf("\tMinimum OS Version: ");
                print_version(build.minos);
                printf("\n\tSDK Version: ");
                print_version(build.sdk);
                printf("\n");
            }
        } else if (lc.cmd == LC_LOAD_DYLINKER) {
            printf("\tDynamic Linker: %s\n", read_string(m->bin, offset + 12));
        }
        offset += lc.cmdsize;
    }
}

static void print_load_commands(const MachOFile *m) {
    size_t offset = first_command(m);

    print_title("Load Commands");
    printf("\t%-4s %-26s %s\n", "Nr", "Command", "Size");
    printf("\t----------------------------------------\n");
    for (uint32_t i = 0; i < m->header.ncmds; i++) {
        LoadCommand lc;
        if (!read_bytes(m->bin, offset, &lc, sizeof(lc)) || lc.cmdsize < sizeof(lc)) break;

        printf("\t%-4u ", i);
        echo_padded(command_name(lc.cmd), "cyan", 26);
        printf(" %u\n", lc.cmdsize);
        offset += lc.cmdsize;
    }

    print_title("Segments");
    printf("\t%-16s %-18s %-12s %-12s %-12s %s\n", "Name", "VM Address", "VM Size", "File Offset", "File Size", "Perms");
    printf("\t------------------------------------------------------------------------------------\n");
    offset = first_command(m);
    for (uint32_t i = 0; i < m->header.ncmds; i++) {
        LoadCommand lc;
        if (!read_bytes(m->bin, offset, &lc, sizeof(lc)) || lc.cmdsize < sizeof(lc)) break;

        if (lc.cmd == LC_SEGMENT || lc.cmd == LC_SEGMENT_64) {
            SegmentCommand64 seg;
            char name[17] = {0};
            char perms[4];

            if (read_segment(m, offset, &seg)) {
                memcpy(name, seg.segname, 16);
                protection_string(seg.initprot, perms);
                printf("\t");
                echo_padded(name, "cyan", 16);
                printf(" 0x%016llX 0x%010llX 0x%010llX 0x%010llX %s\n",
                       (unsigned long long)seg.vmaddr, (unsigned long long)seg.vmsize,
                       (unsigned long long)seg.fileoff, (unsigned long long)seg.filesize, perms);
            }
        }
        offset += lc.cmdsize;
    }
}

static void print_sections(const MachOFile *m) {
    size_t offset = first_command(m);
    size_t section_size = m->is_64 ? sizeof(MachSection64) : sizeof(MachSection32);
    size_t segment_size = m->is_64 ? sizeof(SegmentCommand64) : sizeof(SegmentCommand32);

    print_title("Sections");
    printf("\t%-16s %-20s %-18s %-12s %s\n", "Segment", "Section", "Address", "Size", "File Offset");
    printf("\t-------------------------------------------------------------------------------\n");
    for (uint32_t i = 0; i < m->header.ncmds; i++) {
        LoadCommand lc;
        SegmentCommand64 seg;

        if (!read_bytes(m->bin, offset, &lc, sizeof(lc)) || lc.cmdsize < sizeof(lc)) break;

        if ((lc.cmd == LC_SEGMENT || lc.cmd == LC_SEGMENT_64) && read_segment(m, offset, &seg)) {
            for (uint32_t j = 0; j < seg.nsects; j++) {
                MachSection64 sect;
                char segname[17] = {0};
                char sectname[17] = {0};

                if (!read_section(m, offset + segment_size + j * section_size, &sect)) break;
                memcpy(segname, sect.segname, 16);
                memcpy(sectname, sect.sectname, 16);

                printf("\t%-16s ", segname);
                echo_padded(sectname, "cyan", 20);
                printf(" 0x%016llX 0x%010llX 0x%08X\n",
                       (unsigned long long)sect.addr, (unsigned long long)sect.size, sect.offset);
            }
        }
        offset += lc.cmdsize;
    }
}

static int collect_libraries(const MachOFile *m, const char **names, int max) {
    size_t offset = first_command(m);
    int count = 0;

    for (uint32_t i = 0; i < m->header.ncmds; i++) {
        LoadCommand lc;
        DylibCommand dylib;

        if (!read_bytes(m->bin, offset, &lc, sizeof(lc)) || lc.cmdsize < sizeof(lc)) break;

        if (is_dylib_command(lc.cmd) && count < max && read_bytes(m->bin, offset, &dylib, sizeof(dylib))) {
            names[count] = read_string(m->bin, offset + dylib.name_offset);
            count++;
        }
        offset += lc.cmdsize;
    }
    return count;
}

static void print_libraries(const MachOFile *m) {
    size_t offset = first_command(m);
    int count = 0;

    print_title("Shared Libraries");
    for (uint32_t i = 0; i < m->header.ncmds; i++) {
        LoadCommand lc;
        DylibCommand dylib;

        if (!read_bytes(m->bin, offset, &lc, sizeof(lc)) || lc.cmdsize < sizeof(lc)) break;

        if (is_dylib_command(lc.cmd) && read_bytes(m->bin, offset, &dylib, sizeof(dylib))) {
            printf("\t");
            echo_padded(read_string(m->bin, offset + dylib.name_offset), "red", 60);
            printf(" (version ");
            print_version(dylib.current_version);
            printf(")");
            if (lc.cmd == LC_LOAD_WEAK_DYLIB) printf(" [weak]");
            if (lc.cmd == LC_REEXPORT_DYLIB) printf(" [re-export]");
            printf("\n");
            count++;
        }
        offset += lc.cmdsize;
    }
    if (count == 0) echo("\tNo shared libraries\n", "yellow");
}

static int find_symtab(const MachOFile *m, SymtabCommand *out) {
    size_t offset = first_command(m);

    for (uint32_t i = 0; i < m->header.ncmds; i++) {
        LoadCommand lc;
        if (!read_bytes(m->bin, offset, &lc, sizeof(lc)) || lc.cmdsize < sizeof(lc)) break;
        if (lc.cmd == LC_SYMTAB) return read_bytes(m->bin, offset, out, sizeof(SymtabCommand));
        offset += lc.cmdsize;
    }
    return 0;
}

static const char *library_for_symbol(const char **libraries, int count, uint16_t desc) {
    int ordinal = (desc >> 8) & 0xFF;
    const char *slash;

    if (ordinal == 0) return "(self)";
    if (ordinal == 0xFE) return "(main executable)";
    if (ordinal == 0xFF) return "(flat lookup)";
    if (ordinal > count) return "(unknown)";

    slash = strrchr(libraries[ordinal - 1], '/');
    return slash ? slash + 1 : libraries[ordinal - 1];
}

static void print_symbols(const MachOFile *m, int imported) {
    SymtabCommand symtab;
    const char *libraries[MAX_LIBRARIES];
    int library_count = collect_libraries(m, libraries, MAX_LIBRARIES);
    size_t entry_size = m->is_64 ? sizeof(Nlist64) : sizeof(Nlist32);
    int count = 0;

    print_title(imported ? "Imported Functions" : "Exported Functions");
    if (!find_symtab(m, &symtab)) {
        echo("\tNo symbol table found\n", "yellow");
        return;
    }

    if (imported) printf("\t%-50s %s\n", "Name", "Library");
    else printf("\t%-18s %s\n", "Address", "Name");
    printf("\t------------------------------------------------------------------------\n");

    for (uint32_t i = 0; i < symtab.nsyms; i++) {
        Nlist64 sym;
        const char *name;
        int type;

        if (!read_symbol(m, m->base + symtab.symoff + i * entry_size, &sym)) break;
        if ((sym.n_type & N_STAB) || !(sym.n_type & N_EXT)) continue;

        name = read_string(m->bin, m->base + symtab.stroff + sym.n_strx);
        type = sym.n_type & N_TYPE;

        if (imported && type == N_UNDF) {
            printf("\t");
            echo_padded(name, "green", 50);
            printf(" %s\n", library_for_symbol(libraries, library_count, sym.n_desc));
            count++;
        } else if (!imported && type == N_SECT) {
            printf("\t0x%016llX ", (unsigned long long)sym.n_value);
            echo(name, "green");
            printf("\n");
            count++;
        }
    }

    if (count == 0) echo("\tNothing found\n", "yellow");
}

static void analyze_slice(const Binary *bin, size_t base, const Options *opts) {
    MachOFile m;
    uint32_t magic;

    memset(&m, 0, sizeof(m));
    m.bin = bin;
    m.base = base;

    if (!read_bytes(bin, base, &magic, sizeof(magic))) {
        echo("[!] Invalid Mach-O file\n", "red");
        return;
    }
    if (magic == MACHO_CIGAM_32 || magic == MACHO_CIGAM_64) {
        echo("[!] Big endian Mach-O files are not supported\n", "red");
        return;
    }
    if (magic != MACHO_MAGIC_32 && magic != MACHO_MAGIC_64) {
        echo("[!] Invalid Mach-O magic\n", "red");
        return;
    }

    m.is_64 = magic == MACHO_MAGIC_64;
    if (!read_bytes(bin, base, &m.header, m.is_64 ? sizeof(MachHeader) : sizeof(MachHeader) - 4)) {
        echo("[!] Invalid Mach-O header\n", "red");
        return;
    }

    if (opts->all || opts->file_header) print_header(&m);
    if (opts->all || opts->segments) print_load_commands(&m);
    if (opts->all || opts->sections) print_sections(&m);
    if (opts->all || opts->libraries || opts->imports) print_libraries(&m);
    if (opts->all || opts->imports) print_symbols(&m, 1);
    if (opts->all || opts->exports) print_symbols(&m, 0);
}

static void analyze_fat(const Binary *bin, const Options *opts) {
    FatHeader fat;
    uint32_t count;

    read_bytes(bin, 0, &fat, sizeof(fat));
    count = swap32(fat.nfat_arch);

    print_title("Universal Binary");
    printf("\tNumber of Architectures: %u\n", count);
    for (uint32_t i = 0; i < count; i++) {
        FatArch arch;
        if (!read_bytes(bin, sizeof(FatHeader) + i * sizeof(FatArch), &arch, sizeof(arch))) break;
        printf("\t  - %-8s offset 0x%08X  size %u bytes\n",
               cpu_name(swap32(arch.cputype), swap32(arch.cpusubtype)),
               swap32(arch.offset), swap32(arch.size));
    }

    for (uint32_t i = 0; i < count; i++) {
        FatArch arch;
        if (!read_bytes(bin, sizeof(FatHeader) + i * sizeof(FatArch), &arch, sizeof(arch))) break;

        echo("\n---------------------------------------------------------------------\n", "magenta");
        echo("  Architecture: ", "magenta");
        echo(cpu_name(swap32(arch.cputype), swap32(arch.cpusubtype)), "magenta");
        echo("\n---------------------------------------------------------------------\n", "magenta");
        analyze_slice(bin, swap32(arch.offset), opts);
    }
}

void analyze_macho(const Binary *bin, const Options *opts) {
    uint32_t magic = 0;

    read_bytes(bin, 0, &magic, sizeof(magic));
    if (magic == MACHO_FAT_CIGAM) analyze_fat(bin, opts);
    else analyze_slice(bin, 0, opts);

    if (!opts->all && (opts->dos_header || opts->nt_header || opts->optional_header ||
                       opts->data_directory || opts->relocations)) {
        echo("\n[!] -d -n -o -D -r are only for PE files\n", "yellow");
    }
}

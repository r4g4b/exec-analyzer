#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf.h"
#include "output.h"

static const char *machine_name(uint16_t machine) {
    switch (machine) {
        case 2: return "SPARC";
        case 3: return "Intel 386 (x86)";
        case 8: return "MIPS";
        case 20: return "PowerPC";
        case 21: return "PowerPC 64-bit";
        case 22: return "IBM S/390";
        case 40: return "ARM";
        case 43: return "SPARC V9";
        case 62: return "x86-64 (AMD64)";
        case 94: return "Tensilica Xtensa";
        case 183: return "ARM64 (AArch64)";
        case 243: return "RISC-V";
        case 258: return "LoongArch";
        default: return "Unknown";
    }
}

static const char *os_abi_name(unsigned char abi) {
    switch (abi) {
        case 0: return "UNIX System V";
        case 2: return "NetBSD";
        case 3: return "Linux";
        case 6: return "Solaris";
        case 9: return "FreeBSD";
        case 12: return "OpenBSD";
        case 97: return "ARM";
        case 255: return "Standalone";
        default: return "Unknown";
    }
}

static const char *file_type_name(uint16_t type) {
    switch (type) {
        case 1: return "REL (Relocatable object file)";
        case 2: return "EXEC (Executable file)";
        case 3: return "DYN (Shared object or PIE executable)";
        case 4: return "CORE (Core dump)";
        default: return "Unknown";
    }
}

static const char *section_type_name(uint32_t type) {
    switch (type) {
        case 0: return "NULL";
        case 1: return "PROGBITS";
        case 2: return "SYMTAB";
        case 3: return "STRTAB";
        case 4: return "RELA";
        case 5: return "HASH";
        case 6: return "DYNAMIC";
        case 7: return "NOTE";
        case 8: return "NOBITS";
        case 9: return "REL";
        case 11: return "DYNSYM";
        case 14: return "INIT_ARRAY";
        case 15: return "FINI_ARRAY";
        case 0x6FFFFFF6: return "GNU_HASH";
        case 0x6FFFFFFD: return "VERDEF";
        case 0x6FFFFFFE: return "VERNEED";
        case 0x6FFFFFFF: return "VERSYM";
        default: return "OTHER";
    }
}

static const char *segment_type_name(uint32_t type) {
    switch (type) {
        case 0: return "NULL";
        case 1: return "LOAD";
        case 2: return "DYNAMIC";
        case 3: return "INTERP";
        case 4: return "NOTE";
        case 5: return "SHLIB";
        case 6: return "PHDR";
        case 7: return "TLS";
        case 0x6474E550: return "GNU_EH_FRAME";
        case 0x6474E551: return "GNU_STACK";
        case 0x6474E552: return "GNU_RELRO";
        case 0x6474E553: return "GNU_PROPERTY";
        default: return "OTHER";
    }
}

static const char *symbol_type_name(int type) {
    switch (type) {
        case 0: return "NOTYPE";
        case 1: return "OBJECT";
        case 2: return "FUNC";
        case 3: return "SECTION";
        case 4: return "FILE";
        case 6: return "TLS";
        case 10: return "IFUNC";
        default: return "OTHER";
    }
}

static const char *symbol_bind_name(int bind) {
    switch (bind) {
        case 0: return "LOCAL";
        case 1: return "GLOBAL";
        case 2: return "WEAK";
        case 10: return "UNIQUE";
        default: return "OTHER";
    }
}

int is_elf(const Binary *bin) {
    unsigned char magic[4];
    if (!read_bytes(bin, 0, magic, 4)) return 0;
    return magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

static int read_header(ElfFile *elf) {
    Elf32Header h;

    if (elf->is_64) return read_bytes(elf->bin, 0, &elf->header, sizeof(Elf64Header));
    if (!read_bytes(elf->bin, 0, &h, sizeof(h))) return 0;

    memcpy(elf->header.e_ident, h.e_ident, 16);
    elf->header.e_type = h.e_type;
    elf->header.e_machine = h.e_machine;
    elf->header.e_version = h.e_version;
    elf->header.e_entry = h.e_entry;
    elf->header.e_phoff = h.e_phoff;
    elf->header.e_shoff = h.e_shoff;
    elf->header.e_flags = h.e_flags;
    elf->header.e_ehsize = h.e_ehsize;
    elf->header.e_phentsize = h.e_phentsize;
    elf->header.e_phnum = h.e_phnum;
    elf->header.e_shentsize = h.e_shentsize;
    elf->header.e_shnum = h.e_shnum;
    elf->header.e_shstrndx = h.e_shstrndx;
    return 1;
}

static int read_section(const ElfFile *elf, size_t offset, Elf64Section *out) {
    Elf32Section s;

    if (elf->is_64) return read_bytes(elf->bin, offset, out, sizeof(Elf64Section));
    if (!read_bytes(elf->bin, offset, &s, sizeof(s))) return 0;

    out->sh_name = s.sh_name;
    out->sh_type = s.sh_type;
    out->sh_flags = s.sh_flags;
    out->sh_addr = s.sh_addr;
    out->sh_offset = s.sh_offset;
    out->sh_size = s.sh_size;
    out->sh_link = s.sh_link;
    out->sh_info = s.sh_info;
    out->sh_addralign = s.sh_addralign;
    out->sh_entsize = s.sh_entsize;
    return 1;
}

static int read_segment(const ElfFile *elf, size_t offset, Elf64Segment *out) {
    Elf32Segment p;

    if (elf->is_64) return read_bytes(elf->bin, offset, out, sizeof(Elf64Segment));
    if (!read_bytes(elf->bin, offset, &p, sizeof(p))) return 0;

    out->p_type = p.p_type;
    out->p_flags = p.p_flags;
    out->p_offset = p.p_offset;
    out->p_vaddr = p.p_vaddr;
    out->p_paddr = p.p_paddr;
    out->p_filesz = p.p_filesz;
    out->p_memsz = p.p_memsz;
    out->p_align = p.p_align;
    return 1;
}

static int read_symbol(const ElfFile *elf, size_t offset, Elf64Symbol *out) {
    Elf32Symbol s;

    if (elf->is_64) return read_bytes(elf->bin, offset, out, sizeof(Elf64Symbol));
    if (!read_bytes(elf->bin, offset, &s, sizeof(s))) return 0;

    out->st_name = s.st_name;
    out->st_info = s.st_info;
    out->st_other = s.st_other;
    out->st_shndx = s.st_shndx;
    out->st_value = s.st_value;
    out->st_size = s.st_size;
    return 1;
}

static int read_dynamic(const ElfFile *elf, size_t offset, Elf64Dynamic *out) {
    Elf32Dynamic d;

    if (elf->is_64) return read_bytes(elf->bin, offset, out, sizeof(Elf64Dynamic));
    if (!read_bytes(elf->bin, offset, &d, sizeof(d))) return 0;

    out->d_tag = d.d_tag;
    out->d_val = d.d_val;
    return 1;
}

static int load_elf(ElfFile *elf, const Binary *bin) {
    const Elf64Header *h = &elf->header;

    memset(elf, 0, sizeof(ElfFile));
    elf->bin = bin;
    elf->is_64 = bin->data[4] == ELF_CLASS_64;

    if (!read_header(elf)) return 0;

    if (h->e_shnum > 0) {
        elf->sections = malloc(h->e_shnum * sizeof(Elf64Section));
        if (elf->sections == NULL) return 0;
        for (int i = 0; i < h->e_shnum; i++) {
            if (!read_section(elf, h->e_shoff + (size_t)i * h->e_shentsize, &elf->sections[i])) return 0;
        }
    }

    if (h->e_phnum > 0) {
        elf->segments = malloc(h->e_phnum * sizeof(Elf64Segment));
        if (elf->segments == NULL) return 0;
        for (int i = 0; i < h->e_phnum; i++) {
            if (!read_segment(elf, h->e_phoff + (size_t)i * h->e_phentsize, &elf->segments[i])) return 0;
        }
    }
    return 1;
}

static void free_elf(ElfFile *elf) {
    free(elf->sections);
    free(elf->segments);
    elf->sections = NULL;
    elf->segments = NULL;
}

static const char *section_name(const ElfFile *elf, const Elf64Section *section) {
    if (elf->header.e_shstrndx >= elf->header.e_shnum) return "";
    return read_string(elf->bin, elf->sections[elf->header.e_shstrndx].sh_offset + section->sh_name);
}

static int find_section(const ElfFile *elf, uint32_t type) {
    for (int i = 0; i < elf->header.e_shnum; i++) {
        if (elf->sections[i].sh_type == type) return i;
    }
    return -1;
}

static void print_elf_header(const ElfFile *elf) {
    const Elf64Header *h = &elf->header;

    print_title("ELF Header");
    printf("\tMagic: %02X %02X %02X %02X\n", h->e_ident[0], h->e_ident[1], h->e_ident[2], h->e_ident[3]);
    printf("\tClass: %s\n", elf->is_64 ? "ELF64" : "ELF32");
    printf("\tEndianness: Little Endian\n");
    printf("\tOS/ABI: %s\n", os_abi_name(h->e_ident[7]));
    printf("\tType: %s\n", file_type_name(h->e_type));
    printf("\tArch (Machine): %s (%u)\n", machine_name(h->e_machine), h->e_machine);
    echo("\tEntry Point: ", "green");
    printf("0x%llX\n", (unsigned long long)h->e_entry);
    printf("\tProgram Headers: %u entries at offset 0x%llX\n", h->e_phnum, (unsigned long long)h->e_phoff);
    printf("\tSection Headers: %u entries at offset 0x%llX\n", h->e_shnum, (unsigned long long)h->e_shoff);
    printf("\tFlags: 0x%X\n", h->e_flags);
}

static void print_sections(const ElfFile *elf) {
    print_title("Sections");
    if (elf->header.e_shnum == 0) {
        echo("\tNo section headers\n", "yellow");
        return;
    }

    printf("\t%-4s %-24s %-12s %-18s %-10s %-10s %s\n", "Nr", "Name", "Type", "Address", "Offset", "Size", "Flags");
    printf("\t--------------------------------------------------------------------------------------------\n");
    for (int i = 0; i < elf->header.e_shnum; i++) {
        const Elf64Section *s = &elf->sections[i];
        char flags[4] = "---";

        if (s->sh_flags & 0x2) flags[0] = 'A';
        if (s->sh_flags & 0x1) flags[1] = 'W';
        if (s->sh_flags & 0x4) flags[2] = 'X';

        printf("\t%-4d ", i);
        echo_padded(section_name(elf, s), "cyan", 24);
        printf(" %-12s 0x%016llX 0x%08llX 0x%08llX %s\n", section_type_name(s->sh_type),
               (unsigned long long)s->sh_addr, (unsigned long long)s->sh_offset,
               (unsigned long long)s->sh_size, flags);
    }
}

static void print_segments(const ElfFile *elf) {
    print_title("Program Headers");
    if (elf->header.e_phnum == 0) {
        echo("\tNo program headers\n", "yellow");
        return;
    }

    printf("\t%-14s %-10s %-18s %-10s %-10s %s\n", "Type", "Offset", "Virt Addr", "File Size", "Mem Size", "Perms");
    printf("\t------------------------------------------------------------------------\n");
    for (int i = 0; i < elf->header.e_phnum; i++) {
        const Elf64Segment *p = &elf->segments[i];
        char perms[4] = "---";

        if (p->p_flags & 0x4) perms[0] = 'R';
        if (p->p_flags & 0x2) perms[1] = 'W';
        if (p->p_flags & 0x1) perms[2] = 'X';

        printf("\t");
        echo_padded(segment_type_name(p->p_type), "cyan", 14);
        printf(" 0x%08llX 0x%016llX 0x%08llX 0x%08llX %s\n",
               (unsigned long long)p->p_offset, (unsigned long long)p->p_vaddr,
               (unsigned long long)p->p_filesz, (unsigned long long)p->p_memsz, perms);

        if (p->p_type == ELF_SEGMENT_INTERP) {
            echo("\t    Interpreter: ", "green");
            printf("%s\n", read_string(elf->bin, p->p_offset));
        }
    }
}

static void print_libraries(const ElfFile *elf) {
    int index = find_section(elf, ELF_SECTION_DYNAMIC);
    const Elf64Section *dynamic;
    size_t entry_size = elf->is_64 ? sizeof(Elf64Dynamic) : sizeof(Elf32Dynamic);
    size_t strings;

    print_title("Shared Libraries");
    if (index < 0) {
        echo("\tNo dynamic section (statically linked)\n", "yellow");
        return;
    }

    dynamic = &elf->sections[index];
    if (dynamic->sh_link >= elf->header.e_shnum) return;
    strings = elf->sections[dynamic->sh_link].sh_offset;

    for (size_t i = 0; i < dynamic->sh_size / entry_size; i++) {
        Elf64Dynamic entry;
        if (!read_dynamic(elf, dynamic->sh_offset + i * entry_size, &entry)) break;
        if (entry.d_tag == ELF_DYNAMIC_NULL) break;

        if (entry.d_tag == ELF_DYNAMIC_NEEDED) {
            printf("\t");
            echo(read_string(elf->bin, strings + entry.d_val), "red");
            printf("\n");
        } else if (entry.d_tag == ELF_DYNAMIC_SONAME) {
            printf("\tSoname: %s\n", read_string(elf->bin, strings + entry.d_val));
        } else if (entry.d_tag == ELF_DYNAMIC_RPATH || entry.d_tag == ELF_DYNAMIC_RUNPATH) {
            printf("\tLibrary Path: %s\n", read_string(elf->bin, strings + entry.d_val));
        }
    }
}

static void print_symbols(const ElfFile *elf, int imported) {
    int index = find_section(elf, ELF_SECTION_DYNSYM);
    const Elf64Section *symtab;
    size_t entry_size = elf->is_64 ? sizeof(Elf64Symbol) : sizeof(Elf32Symbol);
    size_t strings;
    int count = 0;

    print_title(imported ? "Imported Functions" : "Exported Functions");
    if (index < 0) index = find_section(elf, ELF_SECTION_SYMTAB);
    if (index < 0) {
        echo("\tNo symbol table found\n", "yellow");
        return;
    }

    symtab = &elf->sections[index];
    if (symtab->sh_link >= elf->header.e_shnum) return;
    strings = elf->sections[symtab->sh_link].sh_offset;

    if (imported) printf("\t%-50s %-8s %s\n", "Name", "Type", "Bind");
    else printf("\t%-18s %-8s %s\n", "Address", "Type", "Name");
    printf("\t------------------------------------------------------------------------\n");

    for (size_t i = 1; i < symtab->sh_size / entry_size; i++) {
        Elf64Symbol sym;
        const char *name;
        int type, bind;

        if (!read_symbol(elf, symtab->sh_offset + i * entry_size, &sym)) break;
        name = read_string(elf->bin, strings + sym.st_name);
        type = sym.st_info & 0xF;
        bind = sym.st_info >> 4;
        if (name[0] == '\0' || bind == 0) continue;

        if (imported && sym.st_shndx == 0) {
            printf("\t");
            echo_padded(name, "green", 50);
            printf(" %-8s %s\n", symbol_type_name(type), symbol_bind_name(bind));
            count++;
        } else if (!imported && sym.st_shndx != 0 && type != 3 && type != 4) {
            printf("\t0x%016llX %-8s ", (unsigned long long)sym.st_value, symbol_type_name(type));
            echo(name, "green");
            printf("\n");
            count++;
        }
    }

    if (count == 0) echo("\tNothing found\n", "yellow");
}

void analyze_elf(const Binary *bin, const Options *opts) {
    ElfFile elf;

    if (bin->size < 16 || (bin->data[4] != ELF_CLASS_32 && bin->data[4] != ELF_CLASS_64)) {
        echo("[!] Invalid ELF class\n", "red");
        return;
    }
    if (bin->data[5] != ELF_DATA_LITTLE) {
        echo("[!] Big endian ELF files are not supported\n", "red");
        return;
    }
    if (!load_elf(&elf, bin)) {
        echo("[!] Invalid or corrupted ELF file\n", "red");
        free_elf(&elf);
        return;
    }

    if (opts->all || opts->file_header) print_elf_header(&elf);
    if (opts->all || opts->sections) print_sections(&elf);
    if (opts->all || opts->segments) print_segments(&elf);
    if (opts->all || opts->libraries || opts->imports) print_libraries(&elf);
    if (opts->all || opts->imports) print_symbols(&elf, 1);
    if (opts->all || opts->exports) print_symbols(&elf, 0);
    if (!opts->all && (opts->dos_header || opts->nt_header || opts->optional_header ||
                       opts->data_directory || opts->relocations)) {
        echo("\n[!] -d -n -o -D -r are only for PE files\n", "yellow");
    }

    free_elf(&elf);
}

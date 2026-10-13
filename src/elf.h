#ifndef ELF_H
#define ELF_H

#include <stdint.h>
#include "binary.h"
#include "options.h"

#define ELF_CLASS_32 1
#define ELF_CLASS_64 2
#define ELF_DATA_LITTLE 1
#define ELF_DATA_BIG 2

#define ELF_SECTION_SYMTAB 2
#define ELF_SECTION_DYNAMIC 6
#define ELF_SECTION_DYNSYM 11

#define ELF_SEGMENT_INTERP 3

#define ELF_DYNAMIC_NULL 0
#define ELF_DYNAMIC_NEEDED 1
#define ELF_DYNAMIC_SONAME 14
#define ELF_DYNAMIC_RPATH 15
#define ELF_DYNAMIC_RUNPATH 29

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf32Header;

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64Header;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
} Elf32Section;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64Section;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} Elf32Segment;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64Segment;

typedef struct {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
} Elf32Symbol;

typedef struct {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64Symbol;

typedef struct {
    int32_t d_tag;
    uint32_t d_val;
} Elf32Dynamic;

typedef struct {
    int64_t d_tag;
    uint64_t d_val;
} Elf64Dynamic;

typedef struct {
    const Binary *bin;
    int is_64;
    Elf64Header header;
    Elf64Section *sections;
    Elf64Segment *segments;
} ElfFile;

int is_elf(const Binary *bin);
void analyze_elf(const Binary *bin, const Options *opts);

#endif

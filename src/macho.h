#ifndef MACHO_H
#define MACHO_H

#include <stdint.h>
#include "binary.h"
#include "options.h"

#define MACHO_MAGIC_32 0xFEEDFACE
#define MACHO_MAGIC_64 0xFEEDFACF
#define MACHO_CIGAM_32 0xCEFAEDFE
#define MACHO_CIGAM_64 0xCFFAEDFE
#define MACHO_FAT_CIGAM 0xBEBAFECA

#define LC_SEGMENT 0x1
#define LC_SYMTAB 0x2
#define LC_LOAD_DYLIB 0xC
#define LC_ID_DYLIB 0xD
#define LC_LOAD_DYLINKER 0xE
#define LC_LOAD_WEAK_DYLIB 0x80000018
#define LC_SEGMENT_64 0x19
#define LC_UUID 0x1B
#define LC_REEXPORT_DYLIB 0x8000001F
#define LC_LAZY_LOAD_DYLIB 0x20
#define LC_LOAD_UPWARD_DYLIB 0x80000023
#define LC_MAIN 0x80000028
#define LC_BUILD_VERSION 0x32

#define N_STAB 0xE0
#define N_TYPE 0x0E
#define N_EXT 0x01
#define N_UNDF 0x0
#define N_SECT 0xE

typedef struct {
    uint32_t magic;
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} MachHeader;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} LoadCommand;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    int32_t maxprot;
    int32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} SegmentCommand32;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t maxprot;
    int32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} SegmentCommand64;

typedef struct {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
} MachSection32;

typedef struct {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} MachSection64;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
} SymtabCommand;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t name_offset;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
} DylibCommand;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
} EntryPointCommand;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t uuid[16];
} UuidCommand;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    uint32_t ntools;
} BuildVersionCommand;

typedef struct {
    uint32_t n_strx;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint32_t n_value;
} Nlist32;

typedef struct {
    uint32_t n_strx;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
} Nlist64;

typedef struct {
    uint32_t magic;
    uint32_t nfat_arch;
} FatHeader;

typedef struct {
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} FatArch;

typedef struct {
    const Binary *bin;
    size_t base;
    int is_64;
    MachHeader header;
} MachOFile;

int is_macho(const Binary *bin);
void analyze_macho(const Binary *bin, const Options *opts);

#endif

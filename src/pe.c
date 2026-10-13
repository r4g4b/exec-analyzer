#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe.h"
#include "output.h"

static const char *machine_name(uint16_t machine) {
    switch (machine) {
        case 0x0000: return "Unknown";
        case 0x014C: return "Intel 386 (x86)";
        case 0x8664: return "x64 (AMD64)";
        case 0x01C0: return "ARM Little Endian";
        case 0x01C2: return "ARM Thumb";
        case 0x01C4: return "ARMv7 Thumb-2 (ARMNT)";
        case 0xAA64: return "ARM64 (AArch64)";
        case 0x0200: return "Intel Itanium (IA-64)";
        case 0x0166: return "MIPS R4000";
        case 0x01F0: return "PowerPC";
        case 0x0EBC: return "EFI Byte Code";
        case 0x5032: return "RISC-V 32-bit";
        case 0x5064: return "RISC-V 64-bit";
        case 0x6264: return "LoongArch 64-bit";
        default: return "Unrecognized";
    }
}

static const char *subsystem_name(uint16_t subsystem) {
    switch (subsystem) {
        case 1: return "Native (drivers and native Windows processes)";
        case 2: return "Windows GUI";
        case 3: return "Windows Console";
        case 5: return "OS/2 Console";
        case 7: return "POSIX Console";
        case 8: return "Native Windows 9x driver";
        case 9: return "Windows CE GUI";
        case 10: return "EFI Application";
        case 11: return "EFI Boot Service Driver";
        case 12: return "EFI Runtime Driver";
        case 13: return "EFI ROM image";
        case 14: return "Xbox";
        case 16: return "Windows Boot Application";
        default: return "Unknown";
    }
}

static const char *directory_name(int index) {
    const char *names[PE_DIRECTORY_COUNT] = {
        "Export Directory", "Import Directory", "Resource Directory",
        "Exception Directory", "Certificate Table", "Base Relocation Table",
        "Debug Directory", "Architecture Reserved", "Global Pointer",
        "TLS Table", "Load Config Table", "Bound Import",
        "Import Address Table", "Delay Import Descriptor", "CLR Runtime Header",
        "Reserved"
    };
    if (index < 0 || index >= PE_DIRECTORY_COUNT) return "Unknown";
    return names[index];
}

static const char *relocation_type_name(int type) {
    switch (type) {
        case 0: return "ABSOLUTE";
        case 1: return "HIGH";
        case 2: return "LOW";
        case 3: return "HIGHLOW";
        case 4: return "HIGHADJ";
        case 5: return "MIPS_JMP";
        case 10: return "DIR64";
        default: return "UNKNOWN";
    }
}

static void convert_optional32(const OptionalHeader32 *in, OptionalHeader64 *out) {
    memset(out, 0, sizeof(OptionalHeader64));
    out->Magic = in->Magic;
    out->MajorLinkerVersion = in->MajorLinkerVersion;
    out->MinorLinkerVersion = in->MinorLinkerVersion;
    out->SizeOfCode = in->SizeOfCode;
    out->SizeOfInitializedData = in->SizeOfInitializedData;
    out->SizeOfUninitializedData = in->SizeOfUninitializedData;
    out->AddressOfEntryPoint = in->AddressOfEntryPoint;
    out->BaseOfCode = in->BaseOfCode;
    out->ImageBase = in->ImageBase;
    out->SectionAlignment = in->SectionAlignment;
    out->FileAlignment = in->FileAlignment;
    out->MajorOperatingSystemVersion = in->MajorOperatingSystemVersion;
    out->MinorOperatingSystemVersion = in->MinorOperatingSystemVersion;
    out->MajorImageVersion = in->MajorImageVersion;
    out->MinorImageVersion = in->MinorImageVersion;
    out->MajorSubsystemVersion = in->MajorSubsystemVersion;
    out->MinorSubsystemVersion = in->MinorSubsystemVersion;
    out->Win32VersionValue = in->Win32VersionValue;
    out->SizeOfImage = in->SizeOfImage;
    out->SizeOfHeaders = in->SizeOfHeaders;
    out->CheckSum = in->CheckSum;
    out->Subsystem = in->Subsystem;
    out->DllCharacteristics = in->DllCharacteristics;
    out->SizeOfStackReserve = in->SizeOfStackReserve;
    out->SizeOfStackCommit = in->SizeOfStackCommit;
    out->SizeOfHeapReserve = in->SizeOfHeapReserve;
    out->SizeOfHeapCommit = in->SizeOfHeapCommit;
    out->LoaderFlags = in->LoaderFlags;
    out->NumberOfRvaAndSizes = in->NumberOfRvaAndSizes;
    memcpy(out->DataDirectory, in->DataDirectory, sizeof(in->DataDirectory));
}

int is_pe(const Binary *bin) {
    DosHeader dos;
    uint32_t signature;

    if (!read_bytes(bin, 0, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != PE_DOS_SIGNATURE) return 0;
    if (!read_bytes(bin, (uint32_t)dos.e_lfanew, &signature, sizeof(signature))) return 0;
    return signature == PE_NT_SIGNATURE;
}

static int load_pe(PeFile *pe, const Binary *bin) {
    uint32_t header_offset;
    uint32_t optional_offset;
    uint32_t sections_offset;
    uint16_t magic;

    memset(pe, 0, sizeof(PeFile));
    pe->bin = bin;

    if (!read_bytes(bin, 0, &pe->dos, sizeof(DosHeader))) return 0;
    header_offset = (uint32_t)pe->dos.e_lfanew;
    if (!read_bytes(bin, header_offset, &pe->signature, sizeof(uint32_t))) return 0;
    if (!read_bytes(bin, header_offset + 4, &pe->file_header, sizeof(FileHeader))) return 0;

    optional_offset = header_offset + 4 + sizeof(FileHeader);
    if (!read_bytes(bin, optional_offset, &magic, sizeof(magic))) return 0;

    if (magic == PE_MAGIC_64) {
        pe->is_64 = 1;
        if (!read_bytes(bin, optional_offset, &pe->optional, sizeof(OptionalHeader64))) return 0;
    } else if (magic == PE_MAGIC_32) {
        OptionalHeader32 optional32;
        if (!read_bytes(bin, optional_offset, &optional32, sizeof(OptionalHeader32))) return 0;
        convert_optional32(&optional32, &pe->optional);
    } else {
        return 0;
    }

    for (int i = pe->optional.NumberOfRvaAndSizes; i < PE_DIRECTORY_COUNT; i++) {
        pe->optional.DataDirectory[i].VirtualAddress = 0;
        pe->optional.DataDirectory[i].Size = 0;
    }

    pe->section_count = pe->file_header.NumberOfSections;
    sections_offset = optional_offset + pe->file_header.SizeOfOptionalHeader;
    if (pe->section_count == 0) return 1;

    pe->sections = malloc(pe->section_count * sizeof(SectionHeader));
    if (pe->sections == NULL) return 0;
    if (!read_bytes(bin, sections_offset, pe->sections, pe->section_count * sizeof(SectionHeader))) {
        free(pe->sections);
        pe->sections = NULL;
        return 0;
    }
    return 1;
}

static int rva_to_offset(const PeFile *pe, uint32_t rva, uint32_t *offset) {
    for (int i = 0; i < pe->section_count; i++) {
        const SectionHeader *section = &pe->sections[i];
        uint32_t size = section->VirtualSize;
        if (size < section->SizeOfRawData) size = section->SizeOfRawData;

        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + size) {
            *offset = rva - section->VirtualAddress + section->PointerToRawData;
            return 1;
        }
    }
    if (rva < pe->optional.SizeOfHeaders) {
        *offset = rva;
        return 1;
    }
    return 0;
}

static const char *string_at_rva(const PeFile *pe, uint32_t rva) {
    uint32_t offset;
    if (!rva_to_offset(pe, rva, &offset)) return "<invalid>";
    return read_string(pe->bin, offset);
}

static void print_dos_header(const PeFile *pe) {
    print_title("DOS Header");
    echo("\tValid Signature: MZ (0x5A4D)\n", "green");
    printf("\tPE Header Offset: 0x%X (%d bytes from start)\n", pe->dos.e_lfanew, pe->dos.e_lfanew);
}

static void print_nt_header(const PeFile *pe) {
    print_title("NT Header");
    printf("\tSignature: 0x%08X => PE\n", pe->signature);
}

static void print_file_characteristics(uint16_t ch) {
    printf("\tCharacteristics: 0x%04X\n", ch);
    if (ch & 0x0002) echo("\t  - Executable File\n", "red");
    if (ch & 0x2000) echo("\t  - DLL File\n", "red");
    if (ch & 0x1000) echo("\t  - System File\n", "red");
    if (ch & 0x0001) printf("\t  - Relocation Info Stripped\n");
    if (ch & 0x0004) printf("\t  - Line Numbers Stripped\n");
    if (ch & 0x0008) printf("\t  - Local Symbols Stripped\n");
    if (ch & 0x0020) printf("\t  - Can Handle Addresses Larger Than 2GB\n");
    if (ch & 0x0100) printf("\t  - 32-Bit Machine\n");
    if (ch & 0x0200) printf("\t  - Debugging Info Stripped\n");
    if (ch & 0x0400) printf("\t  - Copy To Swap File If On Removable Media\n");
    if (ch & 0x0800) printf("\t  - Copy To Swap File If On Network\n");
    if (ch & 0x4000) printf("\t  - Uniprocessor Machine Only\n");
}

static void print_file_header(const PeFile *pe) {
    const FileHeader *fh = &pe->file_header;

    print_title("File Header");
    printf("\tArch (Machine): %s (0x%04X)\n", machine_name(fh->Machine), fh->Machine);
    printf("\tNumber of Sections: %d\n", fh->NumberOfSections);
    echo("\tCompile Time => ", "green");
    print_time(fh->TimeDateStamp);
    printf("\tPointer to Symbol Table: 0x%08X\n", fh->PointerToSymbolTable);
    printf("\tNumber of Symbols: %u\n", fh->NumberOfSymbols);
    printf("\tSize of Optional Header: %d Bytes\n", fh->SizeOfOptionalHeader);
    print_file_characteristics(fh->Characteristics);
}

static void print_dll_characteristics(uint16_t ch) {
    printf("\tDLL Characteristics: 0x%04X\n", ch);
    if (ch & 0x0020) printf("\t  - High Entropy VA (64-bit ASLR)\n");
    if (ch & 0x0040) printf("\t  - Dynamic Base (ASLR)\n");
    if (ch & 0x0080) printf("\t  - Force Integrity Checks\n");
    if (ch & 0x0100) printf("\t  - NX Compatible (DEP)\n");
    if (ch & 0x0200) printf("\t  - No Isolation\n");
    if (ch & 0x0400) printf("\t  - No SEH\n");
    if (ch & 0x0800) printf("\t  - No Bind\n");
    if (ch & 0x1000) printf("\t  - App Container\n");
    if (ch & 0x2000) printf("\t  - WDM Driver\n");
    if (ch & 0x4000) printf("\t  - Control Flow Guard\n");
    if (ch & 0x8000) printf("\t  - Terminal Server Aware\n");
}

static void print_optional_header(const PeFile *pe) {
    const OptionalHeader64 *opt = &pe->optional;
    const char *magic = "Unknown";

    if (opt->Magic == PE_MAGIC_32) magic = "PE32";
    else if (opt->Magic == PE_MAGIC_64) magic = "PE32+ (64-bit)";
    else if (opt->Magic == PE_MAGIC_ROM) magic = "ROM Image";

    print_title("Optional Header");
    printf("\tMagic Value: 0x%04X => %s\n", opt->Magic, magic);
    printf("\tLinker Version: %d.%d\n", opt->MajorLinkerVersion, opt->MinorLinkerVersion);
    printf("\tAddress of Entry Point: 0x%08X\n", opt->AddressOfEntryPoint);
    printf("\tBase of Code: 0x%08X\n", opt->BaseOfCode);
    printf("\tImage Base: 0x%llX\n", (unsigned long long)opt->ImageBase);
    printf("\tSection Alignment: 0x%X\n", opt->SectionAlignment);
    printf("\tFile Alignment: 0x%X\n", opt->FileAlignment);
    printf("\tSize of Code: %u Bytes\n", opt->SizeOfCode);
    printf("\tSize of Image: %u Bytes\n", opt->SizeOfImage);
    printf("\tSize of Headers: %u Bytes\n", opt->SizeOfHeaders);
    printf("\tMinimum OS Version: %d.%d\n", opt->MajorOperatingSystemVersion, opt->MinorOperatingSystemVersion);
    printf("\tSubsystem: %s\n", subsystem_name(opt->Subsystem));
    print_dll_characteristics(opt->DllCharacteristics);
    printf("\tStack Reserve: 0x%llX\n", (unsigned long long)opt->SizeOfStackReserve);
    printf("\tHeap Reserve: 0x%llX\n", (unsigned long long)opt->SizeOfHeapReserve);
    echo("\tData Directory Size: ", "green");
    printf("%u\n", opt->NumberOfRvaAndSizes);
}

static void print_data_directories(const PeFile *pe) {
    print_title("Data Directories");
    printf("\t%-28s | %-10s | %s\n", "Name", "Address", "Size");
    printf("\t--------------------------------------------------------\n");
    for (int i = 0; i < PE_DIRECTORY_COUNT; i++) {
        const DataDirectory *dir = &pe->optional.DataDirectory[i];
        if (dir->VirtualAddress == 0 && dir->Size == 0) continue;
        printf("\t");
        echo_padded(directory_name(i), "cyan", 28);
        printf(" | 0x%08X | %u\n", dir->VirtualAddress, dir->Size);
    }
}

static const char *section_color(const char *name) {
    if (strcmp(name, ".text") == 0) return "cyan";
    if (strcmp(name, ".data") == 0) return "yellow";
    if (strcmp(name, ".rdata") == 0) return "magenta";
    if (strcmp(name, ".rsrc") == 0) return "red";
    if (strcmp(name, ".idata") == 0) return "magenta";
    return "green";
}

static void print_sections(const PeFile *pe) {
    print_title("Sections");
    printf("\t+----------+--------------+--------------+--------------+--------------+-------+\n");
    printf("\t| Name     | Virtual Size | Virtual Addr | Size on Disk | File Offset  | Perms |\n");
    printf("\t+----------+--------------+--------------+--------------+--------------+-------+\n");
    for (int i = 0; i < pe->section_count; i++) {
        const SectionHeader *s = &pe->sections[i];
        char name[9] = {0};
        char perms[4] = "---";

        memcpy(name, s->Name, 8);
        if (s->Characteristics & 0x40000000) perms[0] = 'R';
        if (s->Characteristics & 0x80000000) perms[1] = 'W';
        if (s->Characteristics & 0x20000000) perms[2] = 'X';

        printf("\t| ");
        echo_padded(name, section_color(name), 8);
        printf(" | 0x%08X   | 0x%08X   | 0x%08X   | 0x%08X   | %s   |\n",
               s->VirtualSize, s->VirtualAddress, s->SizeOfRawData, s->PointerToRawData, perms);
    }
    printf("\t+----------+--------------+--------------+--------------+--------------+-------+\n");
}

static void print_dll_name(const char *name) {
    int length = (int)strlen(name);

    printf("\t");
    for (int i = 0; i < length; i++) echo("-", "red");
    printf("\n\t");
    echo(name, "red");
    printf("\n\t");
    for (int i = 0; i < length; i++) echo("-", "red");
    printf("\n");
}

static void print_imported_functions(const PeFile *pe, const ImportDescriptor *desc) {
    uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
    uint32_t thunk_size = pe->is_64 ? 8 : 4;
    uint64_t ordinal_flag = pe->is_64 ? 0x8000000000000000ULL : 0x80000000ULL;
    uint32_t offset;

    if (!rva_to_offset(pe, thunk_rva, &offset)) return;

    while (1) {
        uint64_t thunk = 0;
        if (!read_bytes(pe->bin, offset, &thunk, thunk_size)) break;
        if (thunk == 0) break;

        printf("\t");
        if (thunk & ordinal_flag) {
            echo_padded("(by ordinal)", "yellow", 40);
            printf(" Ordinal: %llu\n", (unsigned long long)(thunk & 0xFFFF));
        } else {
            uint32_t name_rva = (uint32_t)(thunk & 0x7FFFFFFF);
            uint32_t name_offset;
            uint16_t hint = 0;
            const char *name = "<invalid>";

            if (rva_to_offset(pe, name_rva, &name_offset)) {
                read_bytes(pe->bin, name_offset, &hint, sizeof(hint));
                name = read_string(pe->bin, name_offset + 2);
            }
            echo_padded(name, "green", 40);
            printf(" Hint: %u\n", hint);
        }
        offset += thunk_size;
    }
}

static void print_imports(const PeFile *pe, int show_functions) {
    const DataDirectory *dir = &pe->optional.DataDirectory[PE_DIRECTORY_IMPORT];
    uint32_t offset;

    print_title("Import Directory");
    if (dir->VirtualAddress == 0 || !rva_to_offset(pe, dir->VirtualAddress, &offset)) {
        echo("\tNo imports found\n", "yellow");
        return;
    }

    while (1) {
        ImportDescriptor desc;
        if (!read_bytes(pe->bin, offset, &desc, sizeof(desc))) break;
        if (desc.Name == 0) break;

        print_dll_name(string_at_rva(pe, desc.Name));
        if (show_functions) print_imported_functions(pe, &desc);
        offset += sizeof(ImportDescriptor);
    }
}

static void print_exports(const PeFile *pe) {
    const DataDirectory *dir = &pe->optional.DataDirectory[PE_DIRECTORY_EXPORT];
    ExportDirectory exports;
    uint32_t offset, names_offset, ordinals_offset, functions_offset;

    print_title("Export Directory");
    if (dir->VirtualAddress == 0 || !rva_to_offset(pe, dir->VirtualAddress, &offset) ||
        !read_bytes(pe->bin, offset, &exports, sizeof(exports))) {
        echo("\tNo exports found\n", "yellow");
        return;
    }

    printf("\tName: %s\n", string_at_rva(pe, exports.Name));
    printf("\tNumber of Functions: %u\n", exports.NumberOfFunctions);
    printf("\tNumber of Names: %u\n\n", exports.NumberOfNames);

    if (!rva_to_offset(pe, exports.AddressOfNames, &names_offset) ||
        !rva_to_offset(pe, exports.AddressOfNameOrdinals, &ordinals_offset) ||
        !rva_to_offset(pe, exports.AddressOfFunctions, &functions_offset)) {
        return;
    }

    printf("\t%-8s | %-10s | %s\n", "Ordinal", "RVA", "Name");
    printf("\t--------------------------------------------------------\n");
    for (uint32_t i = 0; i < exports.NumberOfNames; i++) {
        uint32_t name_rva = 0;
        uint16_t index = 0;
        uint32_t function_rva = 0;

        if (!read_bytes(pe->bin, names_offset + i * 4, &name_rva, 4)) break;
        if (!read_bytes(pe->bin, ordinals_offset + i * 2, &index, 2)) break;
        read_bytes(pe->bin, functions_offset + index * 4, &function_rva, 4);

        printf("\t%-8u | 0x%08X | ", exports.Base + index, function_rva);
        echo(string_at_rva(pe, name_rva), "green");
        printf("\n");
    }
}

static void print_relocations(const PeFile *pe) {
    const DataDirectory *dir = &pe->optional.DataDirectory[PE_DIRECTORY_RELOCATION];
    uint32_t offset, end;

    print_title("Base Relocations");
    if (dir->VirtualAddress == 0 || !rva_to_offset(pe, dir->VirtualAddress, &offset)) {
        echo("\tNo relocations found\n", "yellow");
        return;
    }

    end = offset + dir->Size;
    while (offset < end) {
        BaseRelocation block;
        int count;

        if (!read_bytes(pe->bin, offset, &block, sizeof(block))) break;
        if (block.VirtualAddress == 0 || block.SizeOfBlock < sizeof(block)) break;

        count = (block.SizeOfBlock - sizeof(block)) / 2;
        printf("\n\t+==============================================+\n");
        printf("\t|  Relocation Block @ RVA: 0x%08X\n", block.VirtualAddress);
        printf("\t|  Block Size: %-5u bytes | Entries: %-3d\n", block.SizeOfBlock, count);
        printf("\t+------------+------------+\n");
        printf("\t|    RVA     |    Type    |\n");
        printf("\t+------------+------------+\n");
        for (int i = 0; i < count; i++) {
            uint16_t entry;
            if (!read_bytes(pe->bin, offset + sizeof(block) + i * 2, &entry, 2)) break;
            printf("\t| 0x%08X | %-10s |\n", block.VirtualAddress + (entry & 0x0FFF),
                   relocation_type_name(entry >> 12));
        }
        printf("\t+------------+------------+\n");
        offset += block.SizeOfBlock;
    }
}

void analyze_pe(const Binary *bin, const Options *opts) {
    PeFile pe;

    if (!load_pe(&pe, bin)) {
        echo("[!] Invalid or unsupported PE file\n", "red");
        return;
    }

    if (opts->all || opts->dos_header) print_dos_header(&pe);
    if (opts->all || opts->nt_header) print_nt_header(&pe);
    if (opts->all || opts->file_header) print_file_header(&pe);
    if (opts->all || opts->optional_header) print_optional_header(&pe);
    if (opts->all || opts->data_directory) print_data_directories(&pe);
    if (opts->all || opts->sections) print_sections(&pe);
    if (opts->all || opts->imports) print_imports(&pe, 1);
    else if (opts->libraries) print_imports(&pe, 0);
    if (opts->all || opts->exports) print_exports(&pe);
    if (opts->all || opts->relocations) print_relocations(&pe);
    if (opts->segments && !opts->all) echo("\n[!] -p is only for ELF and Mach-O files\n", "yellow");

    free(pe.sections);
}

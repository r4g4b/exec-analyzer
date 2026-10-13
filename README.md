# Executable Analyzer

A small command line tool written in C that reads executable files and prints what is inside them. It supports the three main formats:

- **PE** - Windows (`.exe`, `.dll`, `.sys`)
- **ELF** - Linux and most Unix systems (executables, `.so`, `.o`)
- **Mach-O** - macOS and iOS (including universal/fat binaries)

The format is detected automatically from the file's magic bytes, so you just pass the file and the flags you want.

It shows things like the headers, sections, segments, linked libraries, imported functions and exported functions. For PE files it also shows the DOS header, NT header, optional header, data directories and base relocations.

No external libraries are used. All the structures are defined in the project, so it builds the same way on Windows, Linux and macOS.

## Building

You only need a C compiler (gcc or clang) and optionally `make`.

### Linux

Install gcc and make if you don't have them:

```bash
# Debian / Ubuntu
sudo apt install build-essential

# Fedora
sudo dnf install gcc make

# Arch
sudo pacman -S base-devel
```

Then build:

```bash
git clone https://github.com/r4g4b/PEAnalyzer.git
cd PEAnalyzer
make
```

### macOS

Install the Xcode command line tools (this gives you clang and make):

```bash
xcode-select --install
```

Then build:

```bash
git clone https://github.com/r4g4b/PEAnalyzer.git
cd PEAnalyzer
make
```

### Windows

Install [MSYS2](https://www.msys2.org/), open the "MSYS2 UCRT64" terminal and install gcc and make:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc make
```

Then build:

```bash
git clone https://github.com/r4g4b/PEAnalyzer.git
cd PEAnalyzer
make
```

If you don't have `make`, you can compile directly:

```bash
gcc -O2 -o exec_analyzer.exe src/*.c
```

Or with Visual Studio (from the "Developer Command Prompt"):

```bat
cl /O2 /Fe:exec_analyzer.exe src\*.c
```

Colors work in Windows Terminal and in the normal console on Windows 10 and newer.

### Installing system wide (optional)

On Linux and macOS you can copy the binary to a folder in your `PATH`:

```bash
sudo cp exec_analyzer /usr/local/bin/
```

On Windows, put `exec_analyzer.exe` in any folder and add that folder to your `PATH` environment variable.

## Usage

```
exec_analyzer <file> [flags]
```

Flags can be combined, for example `-fsi` is the same as `-f -s -i`.

### Flags for all formats

| Flag | What it shows          |
| ---- | ---------------------- |
| `-a` | Everything             |
| `-f` | File header            |
| `-s` | Sections               |
| `-i` | Linked libraries       |
| `-I` | Imported functions     |
| `-e` | Exported functions     |
| `-h` | Help                   |

### ELF and Mach-O only

| Flag | What it shows                                              |
| ---- | ---------------------------------------------------------- |
| `-p` | Program headers (ELF), load commands and segments (Mach-O) |

### PE only

| Flag | What it shows    |
| ---- | ---------------- |
| `-d` | DOS header       |
| `-n` | NT header        |
| `-o` | Optional header  |
| `-D` | Data directories |
| `-r` | Base relocations |

### Examples

```bash
./exec_analyzer notepad.exe -f -o
./exec_analyzer /bin/ls -i -I
./exec_analyzer libcrypto.so -e
```

Example output for a PE file:

```
[+] File Header [+]
	Arch (Machine): x64 (AMD64) (0x8664)
	Number of Sections: 19
	Compile Time => Thursday 2025-07-31 21:40:07 UTC
	Size of Optional Header: 240 Bytes

[+] Sections [+]
	+----------+--------------+--------------+--------------+--------------+-------+
	| Name     | Virtual Size | Virtual Addr | Size on Disk | File Offset  | Perms |
	+----------+--------------+--------------+--------------+--------------+-------+
	| .text    | 0x00003FE0   | 0x00001000   | 0x00004000   | 0x00000600   | R-X   |
	| .data    | 0x000000C0   | 0x00005000   | 0x00000200   | 0x00004600   | RW-   |
	| .rdata   | 0x00001F38   | 0x00006000   | 0x00002000   | 0x00004800   | R--   |
```

Example output for a Mach-O file:

```
[+] Shared Libraries [+]
	/usr/lib/libutil.dylib            (version 1.0.0)
	/usr/lib/libncurses.5.4.dylib     (version 5.4.0)
	/usr/lib/libSystem.B.dylib        (version 1359.0.0)
```

## Project structure

```
.
├── Makefile
├── README.md
└── src
    ├── main.c        entry point, detects the format and calls the right analyzer
    ├── options.c/h   command line flags
    ├── output.c/h    colored output and small print helpers
    ├── binary.c/h    loads the file into memory and reads from it safely
    ├── pe.c/h        PE structures and analysis
    ├── elf.c/h       ELF structures and analysis
    └── macho.c/h     Mach-O structures and analysis
```

## Notes

- 32-bit and 64-bit files are supported for all three formats.
- For universal (fat) Mach-O files, every architecture inside the file is analyzed.
- Big endian ELF and Mach-O files (old PowerPC, some MIPS) are not supported.
- For PE imports, the `Hint` column is the index the loader tries first in the DLL's export table.
- For Mach-O imports, the library column comes from the two level namespace info in the symbol table.

# DAX — DisAssembler eXtended

<p align="center">
  <pre align="center">
   ██████╗   █████╗ ██╗  ██╗
   ██╔══██╗ ██╔══██╗╚██╗██╔╝
   ██║  ██║ ███████║ ╚███╔╝
   ██║  ██║ ██╔══██║ ██╔██╗
   ██████╔╝ ██║  ██║██╔╝ ██╗
   ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝
  </pre>
</p>

<p align="center">
  <strong>Multi-architecture binary disassembler & reverse engineering tool written in C and Assembly</strong>
</p>

<p align="center">
  <a href="https://github.com/VersaNexusIX/DAX">GitHub</a> ·
  <a href="docs/ARCHITECTURE.md">Architecture</a> ·
  <a href="docs/API.md">API Reference</a> ·
  <a href="docs/CONTRIBUTING.md">Contributing</a>
</p>

---

## Overview

DAX is a lightweight, portable binary disassembler and reverse engineering tool targeting **ELF** (Linux, Android, BSD, UNIX) and **PE** (Windows) binary formats. It supports instruction decoding for **x86\_64**, **ARM64/AArch64**, and **RISC-V 64** architectures, and includes a full analysis pipeline covering CFG construction, loop detection, call graphs, cross-references, and an interactive TUI.

Version: **3.0.0** | License: **BSD 2-Clause**

---

## Features

### Disassembly
- Disassemble ELF32, ELF64, PE32, and PE64+ binaries
- x86\_64 instruction decoder — REX prefix, ModRM, SIB, 1/2-byte opcodes, all major groups
- ARM64/AArch64 instruction decoder — all major encoding groups
- RISC-V 64 instruction decoder — including compressed (C) extension
- Auto-detect OS/ABI: Linux, Android, BSD, UNIX, Windows
- ANSI color output styled after `objdump`/`ndisasm`
- Filter by section name or address range
- Show raw hex bytes alongside instructions

### Analysis
| Flag | Feature |
|------|---------|
| `-y` | Symbol resolution (symtab / dynsym / PE exports) |
| `-d` | C++ Itanium ABI demangling |
| `-f` | Function boundary detection |
| `-g` | Instruction group coloring (call/branch/ret/arith…) |
| `-r` | Cross-reference (xref) annotations |
| `-t` | String reference annotations from `.rodata` |
| `-C` | Control flow graph (basic blocks + edges) |
| `-L` | Loop detection via natural loops / dominators |
| `-G` | Call graph (tree of who calls whom) |
| `-W` | Switch/jump-table detection |
| `-x` | Enable all analysis features above |

### Interactive TUI (`-i`)
A built-in terminal UI for interactive reverse engineering sessions:

| Key | Action |
|-----|--------|
| `j` / `k` / `↑↓` | Navigate instructions |
| `/` | Search mnemonic or operand |
| `.` | Repeat last search |
| `:` | Goto address |
| `r` | Rename symbol |
| `c` | Add comment |
| `n` / `p` | Next / previous function |
| `C` | Show CFG for current function |
| `o` | Save session as `.daxc` |
| `?` / `h` | Help |

### Session Files (`.daxc`)
Save and restore full analysis snapshots — symbols, CFG blocks, xrefs, comments — in the binary `.daxc` format. Convert a `.daxc` back to an annotated `.S` assembly file with `-c`.

---

## Quick Start

```sh
# Basic disassembly
dax ./binary

# Full analysis
dax -x ./binary

# Full analysis + save snapshot
dax -x -o analysis.daxc ./binary

# Convert snapshot to annotated assembly
dax -c analysis.daxc

# Interactive RE session
dax -i -x ./binary

# Disassemble specific section with hex bytes
dax -s .plt -a ./binary

# Filter by address range
dax -A 0x401000 -E 0x402000 ./binary

# List all sections
dax -l ./binary

# No color (for piping)
dax -n ./binary > output.txt
```

---

## Building

> See [docs/BUILDING.md](docs/BUILDING.md) for detailed build instructions.

**Linux / BSD / UNIX / macOS / Android (auto-detected):**
```sh
make
```

**Install to `/usr/local/bin/`:**
```sh
make install
```

**Windows (MinGW):**
```sh
gcc -O2 -Wall -I./include -std=c99 -DOS_WINDOWS \
    src/main.c src/loader.c src/disasm.c \
    src/x86_decode.c src/arm64_decode.c \
    -o dax.exe
```

**Windows (MSVC):**
```sh
cl /O2 /I include /DOS_WINDOWS \
   src\main.c src\loader.c src\disasm.c \
   src\x86_decode.c src\arm64_decode.c \
   /Fe:dax.exe
```

---

## Supported Platforms

| Platform | Arch | Assembly Stub |
|----------|------|---------------|
| Linux | x86\_64 | `arch/x86_64_linux.S` |
| Linux / Android | ARM64 | `arch/arm64_linux.S` |
| BSD (Free/Open/Net/macOS) | x86\_64 | `arch/x86_64_bsd.S` |
| BSD (Free/Open/Net/macOS) | ARM64 | `arch/arm64_bsd.S` |
| Windows (MinGW/MSVC) | x86\_64 | `arch/x86_64_windows.asm` |
| Windows | ARM64 | `arch/arm64_windows.asm` |
| Android (NDK/Termux) | ARM64 / x86\_64 | auto-selected |

---

## Project Structure

```
DAX/
├── include/
│   ├── dax.h          # Main header — structs, constants, function prototypes
│   ├── x86.h          # x86_64 decoder definitions
│   ├── arm64.h        # ARM64 decoder definitions
│   ├── riscv.h        # RISC-V decoder definitions
│   ├── elf.h          # ELF32/ELF64 structs
│   └── pe.h           # PE32/PE64 structs
├── src/
│   ├── main.c         # Entry point, CLI, banner
│   ├── loader.c       # Binary loading, ELF/PE parsing
│   ├── disasm.c       # Disassembler engine, print loop
│   ├── x86_decode.c   # x86_64 instruction decoder
│   ├── arm64_decode.c # ARM64 instruction decoder
│   ├── riscv_decode.c # RISC-V 64 instruction decoder
│   ├── symbols.c      # Symbol table loading & lookup
│   ├── demangle.c     # C++ Itanium ABI demangler
│   ├── analysis.c     # Instruction classification & group colors
│   ├── cfg.c          # Control flow graph builder
│   ├── callgraph.c    # Call graph builder & printer
│   ├── loops.c        # Loop detection (natural loops, dominators)
│   ├── daxc.c         # .daxc format read/write + comments
│   ├── interactive.c  # Interactive TUI (RE mode)
│   └── correct.c      # Correction/suggestion utilities
├── arch/
│   ├── x86_64_linux.S
│   ├── arm64_linux.S
│   ├── x86_64_bsd.S
│   ├── arm64_bsd.S
│   ├── x86_64_windows.asm
│   └── arm64_windows.asm
├── Makefile
└── README
```

---

## Documentation

- [Building DAX](docs/BUILDING.md) — platform-specific build instructions
- [Architecture Overview](docs/ARCHITECTURE.md) — internal design and data flow
- [API Reference](docs/API.md) — public C API and data structures
- [Contributing](docs/CONTRIBUTING.md) — contribution guidelines

---

## License

DAX is released under the **BSD 2-Clause License** — free to use, modify, and redistribute.

---

<p align="center">
  <a href="https://github.com/VersaNexusIX/DAX">https://github.com/VersaNexusIX/DAX</a>
</p>

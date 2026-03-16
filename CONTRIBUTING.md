# Contributing to DAX

> Repository: [https://github.com/VersaNexusIX/DAX](https://github.com/VersaNexusIX/DAX)

Thank you for your interest in contributing to DAX! This document describes conventions, coding style, and the process for submitting changes.

---

## Getting Started

1. **Fork** the repository on GitHub: [https://github.com/VersaNexusIX/DAX](https://github.com/VersaNexusIX/DAX)
2. **Clone** your fork:
   ```sh
   git clone https://github.com/<your-username>/DAX.git
   cd DAX
   ```
3. **Build** to verify everything works:
   ```sh
   make
   ./dax -h
   ```
4. Create a **feature branch**:
   ```sh
   git checkout -b feature/my-improvement
   ```

---

## What to Contribute

All contributions are welcome. Some good areas to work on:

- **New instruction decoders** — for example, adding more complete RISC-V extensions (Zicsr, Zifencei, V vector extension)
- **New analysis passes** — taint analysis, data flow, string detection improvements
- **Architecture support** — MIPS, SPARC, PowerPC, s390x
- **Binary format support** — Mach-O, COFF, raw shellcode with manual base/arch specification
- **Bug fixes** — incorrect decoding of edge-case instructions
- **Documentation** — improving or translating this documentation
- **Testing** — adding test binaries and expected output for regression testing
- **Performance** — profiling and optimizing the disassembly loop

---

## Coding Style

DAX is written in **C99**. Please follow these conventions:

### General

- Use `snake_case` for all identifiers
- Prefix public functions with `dax_` (e.g., `dax_sym_find`)
- Prefix internal/static helpers with no prefix or a short module prefix
- Avoid global mutable state — pass `dax_binary_t *` and `dax_opts_t *` explicitly
- No dynamic memory allocation in hot paths; use pre-allocated arrays with `MAX_*` bounds

### Formatting

- Indent with **4 spaces** — no tabs
- Opening braces on the same line for functions and control flow
- Always use braces for `if`/`for`/`while` bodies, even single-line
- Keep lines under 100 characters where practical

### Example

```c
// Good
static int find_block_by_addr(dax_binary_t *bin, uint64_t addr) {
    int i;
    for (i = 0; i < bin->nblocks; i++) {
        if (bin->blocks[i].start == addr) {
            return i;
        }
    }
    return -1;
}

// Avoid
static int find_block_by_addr(dax_binary_t* bin, uint64_t addr)
{
  for(int i=0;i<bin->nblocks;i++) if(bin->blocks[i].start==addr) return i;
  return -1;
}
```

### Headers

- All public API goes in `include/dax.h`
- Architecture-specific definitions go in `include/x86.h`, `include/arm64.h`, `include/riscv.h`
- Binary format structs go in `include/elf.h` and `include/pe.h`
- No `#pragma once` — use classic `#ifndef` guards

### Portability

DAX targets **C99** and must compile cleanly on:
- GCC and Clang
- Linux, macOS, FreeBSD, OpenBSD, NetBSD
- Android (Termux and NDK)
- Windows (MinGW and MSVC)

Avoid POSIX-only APIs in shared code. Use `#ifdef`/`#if defined()` guards for platform-specific code (see `interactive.c` for the `TERM_UNIX` vs `TERM_WINDOWS` pattern).

---

## Adding a New Instruction Decoder

1. Create `src/<arch>_decode.c` and `include/<arch>.h`
2. Implement a decode function with this signature:
   ```c
   int dax_decode_<arch>(const uint8_t *buf, size_t buf_sz,
                          uint64_t addr, dax_insn_t *out);
   ```
   Returns the number of bytes consumed, or 0 on failure.
3. Implement a classify function:
   ```c
   dax_igrp_t dax_classify_<arch>(const char *mnem);
   ```
4. Add the new `ARCH_<NAME>` value to `dax_arch_t` in `dax.h`
5. Add a dispatch case in `src/disasm.c`
6. Update `dax_arch_str()` in the helpers
7. Update the Makefile to compile the new source file
8. Add the architecture to the documentation

---

## Adding Support for a New Binary Format

1. Add a new `FMT_*` value to `dax_fmt_t`
2. Implement `dax_parse_<format>(dax_binary_t *bin)` in `src/loader.c`
3. Add format detection to `dax_load_binary()` via magic bytes
4. Update `dax_fmt_str()` and related documentation

---

## Submitting a Pull Request

1. Ensure the project builds without warnings on at least Linux x86\_64:
   ```sh
   make clean && make
   ```
2. Test your changes against real binaries:
   ```sh
   ./dax -x /bin/ls
   ./dax -x -i /bin/cat
   ```
3. Commit your changes with a clear message:
   ```
   arch: add MIPS32 instruction decoder

   Adds basic MIPS32 R-type, I-type, and J-type decoding.
   Does not yet support FPU (cop1) instructions.
   ```
4. Push your branch and open a Pull Request against `main` on [https://github.com/VersaNexusIX/DAX](https://github.com/VersaNexusIX/DAX)

### PR Checklist

- [ ] Code compiles cleanly with `-Wall -Wextra`
- [ ] No new warnings introduced
- [ ] Tested against at least one real ELF or PE binary
- [ ] Public API changes are reflected in `include/dax.h` and `docs/API.md`
- [ ] New source files are added to the `SRCS` list in `Makefile`

---

## Reporting Bugs

Open an issue on GitHub: [https://github.com/VersaNexusIX/DAX/issues](https://github.com/VersaNexusIX/DAX/issues)

Please include:

- DAX version (`./dax -h | head -3`)
- OS and architecture (`uname -a`)
- Compiler version (`gcc --version` or `clang --version`)
- The binary that triggered the issue (or a minimal reproducer)
- Expected vs actual output

---

## License

By contributing to DAX, you agree that your contributions will be licensed under the **BSD 2-Clause License**, the same license as the project.

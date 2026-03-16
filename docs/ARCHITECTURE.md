# DAX — Architecture Overview

> Repository: [https://github.com/VersaNexusIX/DAX](https://github.com/VersaNexusIX/DAX)

This document describes the internal design, module responsibilities, and data flow of DAX v3.0.0.

---

## High-Level Design

DAX is structured as a pipeline of loosely coupled modules, all sharing a central `dax_binary_t` context object. The pipeline flows as follows:

```
 ┌─────────────┐
 │  CLI / main │  argument parsing, option struct (dax_opts_t)
 └──────┬──────┘
        │
        ▼
 ┌─────────────┐
 │   loader    │  mmap binary, detect format (ELF/PE/RAW), parse headers
 └──────┬──────┘
        │
        ▼
 ┌─────────────┐
 │   symbols   │  load symtab/dynsym (ELF) or export table (PE)
 └──────┬──────┘
        │
        ▼
 ┌─────────────┐
 │  disasm     │  iterate sections, dispatch to arch decoder, print loop
 └──────┬──────┘
        │
   ┌────┴─────────────────────────────────┐
   ▼         ▼           ▼                ▼
x86_decode  arm64_decode  riscv_decode   analysis
   └────────────────────────────────────────┘
        │
        ▼
 ┌──────────────────────────────────────────┐
 │  optional analysis passes (flags -x …)  │
 │  cfg · callgraph · loops · xrefs        │
 └──────────────────────────────────────────┘
        │
        ▼
 ┌─────────────┐     ┌──────────────────┐
 │  output     │ or  │  interactive TUI │
 │  (stdout)   │     │  (interactive.c) │
 └─────────────┘     └──────────────────┘
        │
        ▼  (optional)
 ┌─────────────┐
 │  daxc       │  serialize/deserialize full analysis snapshot
 └─────────────┘
```

---

## Core Data Structures

All modules communicate through the `dax_binary_t` struct defined in `include/dax.h`.

### `dax_binary_t` — Binary Context

The central object. Holds everything known about a loaded binary.

| Field | Type | Description |
|-------|------|-------------|
| `data` | `uint8_t *` | Raw file contents (mmap'd) |
| `size` | `size_t` | File size in bytes |
| `arch` | `dax_arch_t` | Detected architecture |
| `fmt` | `dax_fmt_t` | Binary format (ELF32/64, PE32/64, RAW) |
| `os` | `dax_os_t` | Detected OS/ABI |
| `entry` | `uint64_t` | Entry point virtual address |
| `base` | `uint64_t` | Load base address |
| `sections[]` | `dax_section_t[64]` | Section table |
| `nsections` | `int` | Number of sections |
| `symbols` | `dax_symbol_t *` | Symbol table (heap-allocated) |
| `nsymbols` | `int` | Symbol count (up to 4096) |
| `xrefs` | `dax_xref_t *` | Cross-references |
| `nxrefs` | `int` | Xref count (up to 8192) |
| `functions` | `dax_func_t *` | Detected function boundaries |
| `nfunctions` | `int` | Function count (up to 2048) |
| `blocks` | `dax_block_t *` | CFG basic blocks |
| `nblocks` | `int` | Block count (up to 16384) |
| `comments` | `dax_comment_t *` | User-added comments |
| `ncomments` | `int` | Comment count (up to 4096) |

### `dax_opts_t` — Runtime Options

Parsed from CLI flags. Controls which features are enabled during a run.

### `dax_insn_t` — Decoded Instruction

| Field | Description |
|-------|-------------|
| `address` | Virtual address |
| `bytes[15]` | Raw opcode bytes |
| `length` | Instruction length in bytes |
| `mnemonic[32]` | Mnemonic string |
| `operands[128]` | Operand string |

---

## Modules

### `src/main.c` — Entry Point

- Parses CLI arguments into `dax_opts_t`
- Prints the DAX banner
- Orchestrates the pipeline: load → symbols → disasm → analysis passes → output/interactive

### `src/loader.c` — Binary Loader

- Memory-maps the file
- Detects binary format by magic bytes (`\x7fELF`, `MZ`)
- Dispatches to `dax_parse_elf()` or `dax_parse_pe()`
- Populates `dax_binary_t.sections[]`, `.arch`, `.fmt`, `.os`, `.entry`, `.base`

**ELF parsing:** Handles both ELF32 and ELF64. Reads the section header table, identifies section types (`SHT_PROGBITS`, `SHT_SYMTAB`, `SHT_DYNSYM`, etc.), and classifies section types using `dax_sec_classify()`.

**PE parsing:** Handles PE32 and PE64+. Reads the PE optional header, section table, and export directory. Detects the target machine (x86\_64 vs ARM64) and OS subsystem.

### `src/disasm.c` — Disassembler Engine

The central disassembly loop:

1. Selects the target section (default: `.text`, or user-specified with `-s`)
2. Applies address range filtering (`-A`/`-E`)
3. Calls the appropriate decoder in a loop: `dax_decode_x86_64()`, `dax_decode_arm64()`, or `dax_decode_riscv64()`
4. After each instruction, annotates with: symbol labels, xref comments, string references, instruction group colors, function boundaries

### `src/x86_decode.c` — x86\_64 Decoder

A hand-written, table-driven x86\_64 decoder. Handles:

- Legacy prefixes (`LOCK`, `REP`, `REPNE`, segment overrides)
- REX prefix (`W`, `R`, `X`, `B` bits)
- 1-byte and 2-byte opcode maps
- ModRM byte: register-direct, register-indirect, SIB, displacement
- SIB byte: base, index, scale
- Immediate values (8/16/32/64-bit)
- All major instruction groups: ALU, data movement, control flow, stack, string, floating point, SIMD, privileged

### `src/arm64_decode.c` — ARM64 Decoder

Decodes AArch64 fixed-width 32-bit instruction words. Handles all major encoding groups:

- Data processing (immediate and register)
- Loads and stores (multiple addressing modes)
- Branches, exceptions, and system instructions
- Floating-point and SIMD (NEON/AdvSIMD)
- Crypto extensions

### `src/riscv_decode.c` — RISC-V 64 Decoder

Decodes RV64GC instruction words. Handles:

- RV32I / RV64I base integer instruction set
- M (multiply/divide), A (atomic), F/D (float), C (compressed 16-bit) extensions
- Variable-length instruction detection (16-bit vs 32-bit)

### `src/symbols.c` — Symbol Resolution

- Loads ELF symbol tables (`SHT_SYMTAB`, `SHT_DYNSYM`) and dynamic string tables
- Loads PE export table entries
- Provides `dax_sym_find(addr)` and `dax_sym_name(addr)` for lookup during disassembly
- Marks the binary entry point as the special `_start` symbol

### `src/demangle.c` — C++ Demangler

An embedded Itanium ABI demangler (no dependency on `libiberty` or `libstdc++`). Used when `-d` is passed to convert mangled C++ names like `_ZN3FooC1Ev` to human-readable form `Foo::Foo()`.

### `src/analysis.c` — Instruction Classification

Maps mnemonic strings to `dax_igrp_t` enum values for all three architectures:

| Group | Examples |
|-------|---------|
| `IGRP_CALL` | `call`, `bl`, `jal` |
| `IGRP_BRANCH` | `jmp`, `jne`, `b.eq`, `beq` |
| `IGRP_RET` | `ret`, `retn`, `iret` |
| `IGRP_SYSCALL` | `syscall`, `svc`, `ecall` |
| `IGRP_ARITHMETIC` | `add`, `sub`, `mul`, `shl` |
| `IGRP_LOGIC` | `and`, `or`, `xor`, `not` |
| `IGRP_DATAMOV` | `mov`, `lea`, `ldr`, `str` |
| `IGRP_STACK` | `push`, `pop`, `enter`, `leave` |
| `IGRP_FLOAT` | `fmul`, `fadd`, `fmov` |
| `IGRP_SIMD` | `vaddps`, `vpcmpeqb` |
| `IGRP_NOP` | `nop`, `endbr64` |
| `IGRP_PRIV` | `hlt`, `cli`, `sti` |

### `src/cfg.c` — Control Flow Graph

Builds a basic-block CFG for a single function:

1. First pass: identify block boundaries (targets of jumps and fall-throughs)
2. Second pass: decode each block, record outgoing edges with edge types (`EDGE_FALL`, `EDGE_JUMP`, `EDGE_COND_TRUE`, `EDGE_COND_FALSE`, `EDGE_CALL`, `EDGE_RET`)
3. Populate predecessor lists
4. Stores results in `dax_binary_t.blocks[]`

`dax_cfg_print()` renders the CFG to stdout with ANSI color-coded edges.

### `src/loops.c` — Loop Detection

Implements natural loop detection using dominator trees:

1. Compute dominator tree via iterative dataflow on the CFG
2. Identify back edges (where a successor dominates the source block)
3. For each back edge, compute the natural loop body
4. Report loops with entry block address, depth, and constituent blocks

### `src/callgraph.c` — Call Graph

Builds and renders a call graph from `dax_binary_t.xrefs`:

1. Filters xrefs where `is_call == 1`
2. Maps source/target addresses to function indices
3. Renders as a depth-first tree with depth limit (max 12 levels) to prevent infinite recursion in self-referencing binaries

### `src/daxc.c` — Snapshot Format

Implements the `.daxc` binary snapshot format (magic `DAXC`, version 3):

**Write (`dax_daxc_write`):** Serializes `dax_binary_t` — sections, symbols, xrefs, functions, CFG blocks, comments, and all decoded instructions — into a compact binary file.

**Read (`dax_daxc_read`):** Restores the full analysis state from a `.daxc` file.

**Convert (`dax_daxc_to_asm`):** Generates an annotated `.S` assembly source from a `.daxc` file, with symbol labels and inline comments.

The format header (`daxc_header_t`) is packed and uses fixed offsets for each section, making it portable across platforms.

### `src/interactive.c` — Interactive TUI

A terminal-based reverse engineering UI using raw terminal mode (`termios` on POSIX, `conio.h`/`windows.h` on Windows).

**Modes:**
- `MODE_NORMAL` — navigate and view instructions
- `MODE_SEARCH` — `/` search by mnemonic/operand substring
- `MODE_GOTO` — `:` jump to hex address
- `MODE_RENAME` — `r` rename a symbol at cursor
- `MODE_COMMENT` — `c` annotate an instruction with a comment
- `MODE_SAVE` — `o` specify output `.daxc` filename

The TUI pre-loads all instructions into a `view_insn_t[]` array (up to 65536 entries) for O(1) random access during navigation.

### `src/correct.c` — Correction Utilities

Provides suggestions and correctional output, for example when the user invokes DAX with an unrecognized flag or malformed arguments.

---

## `.daxc` File Format

```
Offset 0         : daxc_header_t (packed, 64-byte reserved padding)
off_sections     : dax_section_t[] × nsections
off_symbols      : dax_symbol_t[]  × nsymbols
off_xrefs        : dax_xref_t[]    × nxrefs
off_functions    : dax_func_t[]    × nfunctions
off_blocks       : dax_block_t[]   × nblocks
off_comments     : dax_comment_t[] × ncomments
off_insns        : daxc_insn_t[]   × ninsns
```

Magic: `0x43584144` (`"DAXC"` little-endian)

---

## ANSI Color Scheme

DAX uses a consistent color vocabulary across all output:

| Constant | Color | Used For |
|----------|-------|---------|
| `COL_ADDR` | Blue bold | Instruction addresses |
| `COL_BYTES` | Dark gray | Hex byte dump |
| `COL_MNEM` | White bold | Mnemonics |
| `COL_OPS` | Cyan | Operands |
| `COL_LABEL` | Yellow bold | Jump/call labels |
| `COL_SYM` | Magenta bold | Symbol names |
| `COL_FUNC` | Cyan bold | Function names |
| `COL_XREF` | Yellow | Xref annotations |
| `COL_STRING` | Green | String references |
| `COL_GRP_CALL` | Yellow bold | Call instructions |
| `COL_GRP_RET` | Red bold | Return instructions |
| `COL_GRP_SYS` | Red bold | Syscall instructions |
| `COL_CFG_TRUE` | Green | CFG true branch |
| `COL_CFG_FALSE` | Red | CFG false branch |
| `COL_RISCV_C` | Yellow | RISC-V compressed insns |

All color output is suppressed when `-n` is passed or when stdout is not a TTY.

# DAX — API Reference

> Repository: [https://github.com/VersaNexusIX/DAX](https://github.com/VersaNexusIX/DAX)

All public functions and types are declared in `include/dax.h`.

---

## Enumerations

### `dax_arch_t` — Architecture

```c
typedef enum {
    ARCH_UNKNOWN = 0,
    ARCH_X86_64,
    ARCH_ARM64,
    ARCH_RISCV64
} dax_arch_t;
```

### `dax_fmt_t` — Binary Format

```c
typedef enum {
    FMT_UNKNOWN = 0,
    FMT_ELF32,
    FMT_ELF64,
    FMT_PE32,
    FMT_PE64,
    FMT_RAW
} dax_fmt_t;
```

### `dax_os_t` — Operating System / ABI

```c
typedef enum {
    DAX_PLAT_UNKNOWN = 0,
    DAX_PLAT_LINUX,
    DAX_PLAT_ANDROID,
    DAX_PLAT_BSD,
    DAX_PLAT_UNIX,
    DAX_PLAT_WINDOWS
} dax_os_t;
```

### `dax_sym_type_t` — Symbol Type

```c
typedef enum {
    SYM_UNKNOWN = 0,
    SYM_FUNC,
    SYM_OBJECT,
    SYM_IMPORT,
    SYM_EXPORT,
    SYM_WEAK,
    SYM_LOCAL
} dax_sym_type_t;
```

### `dax_igrp_t` — Instruction Group

```c
typedef enum {
    IGRP_UNKNOWN = 0,
    IGRP_PROLOGUE,
    IGRP_EPILOGUE,
    IGRP_CALL,
    IGRP_BRANCH,
    IGRP_RET,
    IGRP_SYSCALL,
    IGRP_ARITHMETIC,
    IGRP_LOGIC,
    IGRP_DATAMOV,
    IGRP_COMPARE,
    IGRP_STACK,
    IGRP_STRING,
    IGRP_FLOAT,
    IGRP_SIMD,
    IGRP_CRYPTO,
    IGRP_NOP,
    IGRP_PRIV
} dax_igrp_t;
```

### `dax_sec_type_t` — Section Type

```c
typedef enum {
    SEC_TYPE_CODE,
    SEC_TYPE_DATA,
    SEC_TYPE_RODATA,
    SEC_TYPE_BSS,
    SEC_TYPE_PLT,
    SEC_TYPE_GOT,
    SEC_TYPE_DYNAMIC,
    SEC_TYPE_DEBUG,
    SEC_TYPE_OTHER
} dax_sec_type_t;
```

### `dax_edge_type_t` — CFG Edge Type

```c
typedef enum {
    EDGE_FALL = 0,       // Fall-through to next block
    EDGE_JUMP,           // Unconditional jump
    EDGE_COND_TRUE,      // Conditional branch taken
    EDGE_COND_FALSE,     // Conditional branch not taken
    EDGE_CALL,           // Function call
    EDGE_RET             // Return edge
} dax_edge_type_t;
```

---

## Structs

### `dax_insn_t` — Decoded Instruction

```c
typedef struct {
    uint64_t  address;
    uint8_t   bytes[15];   // DAX_MAX_INSN_LEN
    uint8_t   length;
    char      mnemonic[32];
    char      operands[128];
} dax_insn_t;
```

### `dax_section_t` — Section Entry

```c
typedef struct {
    char            name[32];
    uint64_t        offset;    // File offset
    uint64_t        vaddr;     // Virtual address
    uint64_t        size;
    uint32_t        flags;
    dax_sec_type_t  type;
} dax_section_t;
```

### `dax_symbol_t` — Symbol Entry

```c
typedef struct {
    uint64_t        address;
    char            name[256];
    char            demangled[256];
    dax_sym_type_t  type;
    uint64_t        size;
    int             is_entry;
} dax_symbol_t;
```

### `dax_xref_t` — Cross-Reference

```c
typedef struct {
    uint64_t  from;      // Source address
    uint64_t  to;        // Target address
    int       is_call;   // 1 if call, 0 if jump
} dax_xref_t;
```

### `dax_func_t` — Detected Function

```c
typedef struct {
    uint64_t  start;
    uint64_t  end;
    char      name[256];
    int       sym_idx;   // Index into symbols[], or -1
} dax_func_t;
```

### `dax_block_t` — CFG Basic Block

```c
typedef struct {
    uint64_t         start;
    uint64_t         end;
    int              func_idx;
    int              id;
    int              succ[4];          // Successor block IDs
    int              nsucc;
    int              pred[4];          // Predecessor block IDs
    int              npred;
    dax_edge_type_t  edge_type[4];
    int              is_entry;
    int              is_exit;
} dax_block_t;
```

### `dax_comment_t` — Instruction Comment

```c
typedef struct {
    uint64_t  address;
    char      text[256];
} dax_comment_t;
```

### `dax_binary_t` — Binary Context

```c
typedef struct {
    uint8_t       *data;
    size_t         size;
    dax_arch_t     arch;
    dax_fmt_t      fmt;
    dax_os_t       os;
    uint64_t       entry;
    uint64_t       base;
    dax_section_t  sections[64];
    int            nsections;
    char           filepath[512];
    dax_symbol_t  *symbols;
    int            nsymbols;
    dax_xref_t    *xrefs;
    int            nxrefs;
    dax_func_t    *functions;
    int            nfunctions;
    dax_block_t   *blocks;
    int            nblocks;
    dax_comment_t *comments;
    int            ncomments;
} dax_binary_t;
```

### `dax_opts_t` — Runtime Options

```c
typedef struct {
    int      show_bytes;    // -a
    int      show_addr;
    int      color;         // disabled with -n
    int      verbose;       // -v
    int      symbols;       // -y
    int      xrefs;         // -r
    int      groups;        // -g
    int      strings;       // -t
    int      funcs;         // -f
    int      demangle;      // -d
    int      all_sections;  // -S
    int      cfg;           // -C
    int      loops;         // -L
    int      callgraph;     // -G
    int      switches;      // -W
    int      interactive;   // -i
    char     section[32];   // -s <name>
    char     output_daxc[512]; // -o <file.daxc>
    uint64_t start_addr;    // -A <addr>
    uint64_t end_addr;      // -E <addr>
} dax_opts_t;
```

---

## Functions

### Loading

```c
int dax_load_binary(const char *path, dax_binary_t *bin);
```
Load and memory-map a binary file. Detects format (ELF/PE) and parses headers. Returns 0 on success, -1 on error.

```c
int dax_parse_elf(dax_binary_t *bin);
int dax_parse_pe(dax_binary_t *bin);
```
Parse ELF or PE headers from an already-loaded `dax_binary_t`. Called internally by `dax_load_binary`.

```c
void dax_free_binary(dax_binary_t *bin);
```
Free all heap-allocated fields within `bin` (symbols, xrefs, functions, blocks, comments). Does not free `bin` itself.

---

### Disassembly

```c
int dax_disasm_x86_64(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
int dax_disasm_arm64 (dax_binary_t *bin, dax_opts_t *opts, FILE *out);
int dax_disasm_riscv64(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Run the disassembly loop for the selected section and output to `out`. Applies address filtering, symbol annotations, xref comments, and group coloring according to `opts`. Returns the number of instructions decoded, or -1 on error.

---

### Output

```c
void dax_print_banner(dax_binary_t *bin, dax_opts_t *opts);
```
Print the DAX banner with detected arch, format, OS, entry point, and section count.

```c
void dax_print_sections(dax_binary_t *bin, dax_opts_t *opts);
```
Print a color-coded table of all sections (`-l` flag).

---

### Symbols

```c
int           dax_sym_load(dax_binary_t *bin);
```
Load symbol table from ELF `.symtab`/`.dynsym` or PE export directory into `bin->symbols[]`. Returns symbol count.

```c
dax_symbol_t *dax_sym_find(dax_binary_t *bin, uint64_t addr);
```
Find the symbol whose address matches `addr` exactly. Returns `NULL` if not found.

```c
const char   *dax_sym_name(dax_binary_t *bin, uint64_t addr);
```
Return the (possibly demangled) name for the symbol at `addr`, or `NULL`.

---

### Cross-References

```c
int dax_xref_build(dax_binary_t *bin);
```
Scan all decoded instructions for call and jump targets. Populates `bin->xrefs[]`. Returns xref count.

```c
int dax_xref_find_to(dax_binary_t *bin, uint64_t addr,
                      dax_xref_t *out, int max);
```
Find all xrefs that target `addr`. Writes up to `max` entries into `out[]`. Returns count found.

---

### Functions

```c
int dax_func_detect(dax_binary_t *bin, uint8_t *code, size_t sz,
                     uint64_t base, dax_section_t *sec);
```
Detect function boundaries within a code region using symbol table hints and prologue/epilogue heuristics. Populates `bin->functions[]`.

```c
dax_func_t *dax_func_find(dax_binary_t *bin, uint64_t addr);
```
Return the function that contains `addr`, or `NULL`.

---

### Demangling

```c
int dax_demangle(const char *mangled, char *out, size_t outsz);
```
Demangle a C++ Itanium ABI symbol. Writes result to `out`. Returns 1 on success, 0 if not a mangled name.

---

### Instruction Classification

```c
dax_igrp_t  dax_classify_x86(const char *mnem);
dax_igrp_t  dax_classify_arm64(const char *mnem);
dax_igrp_t  dax_classify_riscv(const char *mnem);
```
Return the instruction group for a given mnemonic string.

```c
const char *dax_igrp_str(dax_igrp_t g);
```
Return a human-readable name for an instruction group.

```c
dax_sec_type_t dax_sec_classify(const char *name, uint32_t flags);
```
Classify a section by its name and ELF/PE flags.

---

### Control Flow Graph

```c
int dax_cfg_build(dax_binary_t *bin, uint8_t *code, size_t sz,
                   uint64_t base, int func_idx);
```
Build the CFG for function `func_idx`. Populates `bin->blocks[]`. Returns block count, or -1 on error.

```c
int dax_cfg_print(dax_binary_t *bin, int func_idx,
                   dax_opts_t *opts, FILE *out);
```
Print the CFG of function `func_idx` to `out` with ANSI colors.

---

### Loop Detection

```c
int  dax_loop_detect(dax_binary_t *bin, int func_idx, FILE *out, int color);
void dax_loop_print_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Detect and print natural loops for a single function or all functions.

---

### Call Graph

```c
void dax_callgraph_print(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
```
Print the full call graph as a depth-first tree.

---

### Switch Detection

```c
void dax_switch_detect(dax_binary_t *bin, dax_opts_t *opts,
                        uint8_t *code, size_t sz, uint64_t base, FILE *out);
```
Scan for `cmp` + jump-table patterns and report detected switch statements.

---

### Comments

```c
void        dax_comment_add(dax_binary_t *bin, uint64_t addr, const char *text);
const char *dax_comment_get(dax_binary_t *bin, uint64_t addr);
```
Add or retrieve an inline comment for a given instruction address. Comments are persisted in `.daxc` snapshots.

---

### Interactive Mode

```c
int dax_interactive(dax_binary_t *bin, dax_opts_t *opts);
```
Enter the interactive terminal UI. Returns 0 on clean exit.

---

### `.daxc` Snapshot Format

```c
int dax_daxc_write(dax_binary_t *bin, dax_opts_t *opts, const char *path);
```
Serialize a full analysis snapshot to `path`. Returns 0 on success.

```c
int dax_daxc_read(const char *path, dax_binary_t *bin);
```
Restore a full analysis snapshot from `path` into `bin`. Returns 0 on success.

```c
int dax_daxc_to_asm(const char *daxc_path, const char *asm_path, int color);
```
Convert a `.daxc` snapshot to an annotated `.S` assembly source file. Pass `color=1` to emit ANSI colors, `color=0` for plain text.

---

### String Helpers

```c
const char *dax_arch_str(dax_arch_t a);
const char *dax_fmt_str(dax_fmt_t f);
const char *dax_os_str(dax_os_t o);
```
Return a human-readable string for the given enum value.

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DAX_VERSION` | `"3.0.0"` | Library version string |
| `DAX_MAX_INSN_LEN` | 15 | Max instruction byte length |
| `DAX_MAX_MNEMONIC` | 32 | Mnemonic buffer size |
| `DAX_MAX_OPERANDS` | 128 | Operand buffer size |
| `DAX_MAX_SECTIONS` | 64 | Max sections per binary |
| `DAX_MAX_SYMBOLS` | 4096 | Max symbols per binary |
| `DAX_MAX_XREFS` | 8192 | Max cross-references |
| `DAX_MAX_FUNCTIONS` | 2048 | Max detected functions |
| `DAX_MAX_BLOCKS` | 16384 | Max CFG basic blocks |
| `DAX_MAX_EDGES` | 32768 | Max CFG edges |
| `DAX_MAX_COMMENTS` | 4096 | Max user comments |
| `DAX_DAXC_MAGIC` | `0x43584144` | `.daxc` file magic (`DAXC`) |
| `DAX_DAXC_VERSION` | 3 | `.daxc` format version |

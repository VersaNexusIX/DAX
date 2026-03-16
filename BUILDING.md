# Building DAX

This document covers how to compile DAX on all supported platforms.

> Repository: [https://github.com/VersaNexusIX/DAX](https://github.com/VersaNexusIX/DAX)

---

## Requirements

- A C99-compliant compiler: **GCC** or **Clang** (auto-detected by Makefile)
- **GNU Make** (for Linux/BSD/macOS/Android)
- For Windows: **MinGW**, **MSVC**, or **Clang for Windows**
- No external library dependencies — DAX is fully self-contained

---

## Linux / macOS / BSD / UNIX

The Makefile auto-detects your OS, architecture, and compiler.

```sh
git clone https://github.com/VersaNexusIX/DAX.git
cd DAX
make
```

After a successful build, the binary is placed at `./dax`.

**Install to `/usr/local/bin/`:**
```sh
make install
```

**Clean build artifacts:**
```sh
make clean
```

**Show build info (detected platform, compiler, flags):**
```sh
make info
```

### Platform Details

| Platform | Compiler Preference | Define |
|----------|-------------------|--------|
| Linux | GCC → Clang → cc | `-DBUILD_OS_LINUX -D_GNU_SOURCE` |
| macOS (Darwin) | Clang → GCC | `-DBUILD_OS_BSD` |
| FreeBSD | Clang → GCC | `-DBUILD_OS_BSD` |
| OpenBSD | Clang | `-DBUILD_OS_BSD` |
| NetBSD | GCC → Clang | `-DBUILD_OS_BSD`, installs to `/usr/pkg` |

---

## Android

### Termux (on-device build)

DAX builds natively inside Termux without any cross-compilation setup.

```sh
pkg install clang make
git clone https://github.com/VersaNexusIX/DAX.git
cd DAX
make
```

The Makefile detects the Termux `$PREFIX` variable and selects `clang` automatically.

### NDK Cross-Compile (ARM64)

```sh
export NDK_TOOLCHAIN=/path/to/ndk/toolchain
export API=21
make android
```

### NDK Cross-Compile (x86\_64)

```sh
export NDK_TOOLCHAIN=/path/to/ndk/toolchain
export API=21
make android-x86
```

On Android, the binary installs to `/system/xbin/dax` (or `$PREFIX/bin/dax` on Termux).

---

## Windows

### MinGW (GCC)

```sh
gcc -O2 -Wall -I./include -std=c99 -DOS_WINDOWS \
    src/main.c src/loader.c src/disasm.c \
    src/x86_decode.c src/arm64_decode.c \
    src/symbols.c src/demangle.c src/analysis.c \
    src/cfg.c src/daxc.c src/interactive.c \
    src/loops.c src/callgraph.c src/correct.c \
    src/riscv_decode.c \
    -o dax.exe
```

### MSVC (Developer Command Prompt)

```bat
cl /O2 /I include /DOS_WINDOWS ^
   src\main.c src\loader.c src\disasm.c ^
   src\x86_decode.c src\arm64_decode.c ^
   src\symbols.c src\demangle.c src\analysis.c ^
   src\cfg.c src\daxc.c src\interactive.c ^
   src\loops.c src\callgraph.c src\correct.c ^
   src\riscv_decode.c ^
   /Fe:dax.exe
```

On Windows the interactive TUI uses `<windows.h>` and `<conio.h>` instead of the POSIX `termios` API, handled automatically via `#ifdef`.

---

## Compiler Flags

The Makefile applies the following base flags to all platforms:

```
-O2 -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter
-Wno-unused-function -I./include -std=c99
```

Additional GCC-specific flags:
```
-Wno-stringop-truncation -Wno-format-truncation
-Wno-format-extra-args -Wno-tautological-compare
```

Additional Clang-specific flags:
```
-Wno-format-truncation -Wno-format-extra-args
-Wno-tautological-compare -Wno-gnu-variable-sized-type-not-at-end
```

---

## Assembly Stubs

Each platform links in a native assembly stub for low-level operations. The Makefile selects the correct stub automatically based on detected OS and architecture:

| File | Platform | Arch |
|------|----------|------|
| `arch/x86_64_linux.S` | Linux / Android | x86\_64 |
| `arch/arm64_linux.S` | Linux / Android | ARM64 |
| `arch/x86_64_bsd.S` | BSD / macOS | x86\_64 |
| `arch/arm64_bsd.S` | BSD / macOS | ARM64 |
| `arch/x86_64_windows.asm` | Windows | x86\_64 (MASM/ml64) |
| `arch/arm64_windows.asm` | Windows | ARM64 (armasm64) |

---

## Troubleshooting

**`command not found: make`**
Install `build-essential` (Debian/Ubuntu), `base-devel` (Arch), or `xcode-select --install` (macOS).

**Linker errors on BSD**
Ensure you are using the system `clang`, not a Homebrew GCC that may lack BSD-specific headers.

**Windows: interactive mode does not display correctly**
The TUI requires a terminal that supports ANSI escape codes. Use Windows Terminal or a modern `cmd.exe`. Legacy `cmd.exe` on Windows 7/8 may not support ANSI.

---

## Verifying the Build

After building, run:

```sh
./dax -h
```

You should see the DAX banner and full usage information. Run a quick test:

```sh
./dax -l /bin/ls
```

This lists all ELF sections inside the system `ls` binary.

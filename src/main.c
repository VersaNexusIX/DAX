#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"

static void print_usage(void) {
    const char *R  = "\033[0m";
    const char *B  = "\033[1;34m";
    const char *Y  = "\033[1;33m";
    const char *W  = "\033[1;37m";
    const char *G  = "\033[1;32m";
    const char *C  = "\033[1;36m";
    const char *M  = "\033[1;35m";
    const char *DG = "\033[0;90m";
    const char *RD = "\033[1;31m";
    FILE *o = stderr;

    fprintf(o, "\n");
    fprintf(o, "%s ██████╗   █████╗ ██╗  ██╗%s\n", Y, R);
    fprintf(o, "%s ██╔══██╗ ██╔══██╗╚██╗██╔╝%s\n", Y, R);
    fprintf(o, "%s ██║  ██║ ███████║ ╚███╔╝ %s  %sv%s%s\n", Y, R, DG, DAX_VERSION, R);
    fprintf(o, "%s ██║  ██║ ██╔══██║ ██╔██╗ %s  %sBinary Disassembler & RE Tool%s\n", Y, R, DG, R);
    fprintf(o, "%s ██████╔╝ ██║  ██║██╔╝ ██╗%s\n", Y, R);
    fprintf(o, "%s ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝%s\n", Y, R);
    fprintf(o, "\n");

    fprintf(o, "%s  Usage%s  dax %s[options]%s %s<binary>%s | dax %s[options]%s %s<file.daxc>%s\n",
            W, R, DG, R, G, R, DG, R, C, R);
    fprintf(o, "\n");

    fprintf(o, "%s╔══════════════════════╗%s\n", B, R);
    fprintf(o, "%s║  DISASSEMBLY         ║%s\n", B, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", B, R);
    fprintf(o, "  %s-a%s              %sshow hex bytes alongside each instruction%s\n", W, R, DG, R);
    fprintf(o, "  %s-s%s %s<section>%s    %sdisassemble a specific section%s  %s(default: .text)%s\n", W, R, C, R, DG, R, DG, R);
    fprintf(o, "  %s-S%s              %sdisassemble ALL executable sections%s\n", W, R, DG, R);
    fprintf(o, "  %s-A%s %s<addr>%s       %sstart address in hex%s\n", W, R, C, R, DG, R);
    fprintf(o, "  %s-E%s %s<addr>%s       %send address in hex%s\n", W, R, C, R, DG, R);
    fprintf(o, "  %s-l%s              %slist all sections with type & color coding%s\n", W, R, DG, R);
    fprintf(o, "\n");

    fprintf(o, "%s╔══════════════════════╗%s\n", G, R);
    fprintf(o, "%s║  ANALYSIS            ║%s\n", G, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", G, R);
    fprintf(o, "  %s-y%s              %sresolve symbols from symtab / dynsym / PE exports%s\n", W, R, DG, R);
    fprintf(o, "  %s-d%s              %sdemangle C++ Itanium ABI symbols%s\n", W, R, DG, R);
    fprintf(o, "  %s-f%s              %sdetect function boundaries & sizes%s\n", W, R, DG, R);
    fprintf(o, "  %s-g%s              %sinstruction group coloring%s  %s(call/branch/ret/arith...)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-r%s              %scross-reference annotations%s  %s(who calls what)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-t%s              %sannotate string references from .rodata%s\n", W, R, DG, R);
    fprintf(o, "  %s-C%s              %scontrol flow graph%s  %s(basic blocks + edges)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-L%s              %sloop detection%s  %s(natural loops via dominators)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-G%s              %scall graph%s  %s(who calls who, tree view)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-W%s              %sswitch detection%s  %s(jump table patterns)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-L%s              %sloop detection%s  %s(natural loops, back-edges, dominators)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-G%s              %scall graph%s  %s(tree of who calls who)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-W%s              %sswitch detection%s  %s(cmp+jmp table patterns)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-x%s              %senable everything above%s  %s(-y -d -f -g -r -t -C -L -G -W)%s\n", RD, R, DG, R, DG, R);
    fprintf(o, "\n");

    fprintf(o, "%s╔══════════════════════╗%s\n", M, R);
    fprintf(o, "%s║  INTERACTIVE MODE    ║%s\n", M, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", M, R);
    fprintf(o, "  %s-i%s              %slaunch interactive RE TUI%s\n", W, R, DG, R);
    fprintf(o, "  %s  j/k ↑↓%s       %snavigate instructions%s\n", C, R, DG, R);
    fprintf(o, "  %s  / . :%s        %ssearch / repeat / goto address%s\n", C, R, DG, R);
    fprintf(o, "  %s  r c%s          %srename symbol / add comment%s\n", C, R, DG, R);
    fprintf(o, "  %s  n p%s          %snext / previous function%s\n", C, R, DG, R);
    fprintf(o, "  %s  C%s            %sshow CFG for current function%s\n", C, R, DG, R);
    fprintf(o, "  %s  o%s            %ssave session as .daxc%s\n", C, R, DG, R);
    fprintf(o, "  %s  ? h%s          %shelp inside interactive mode%s\n", C, R, DG, R);
    fprintf(o, "\n");

    fprintf(o, "%s╔══════════════════════╗%s\n", C, R);
    fprintf(o, "%s║  OUTPUT / FILES      ║%s\n", C, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", C, R);
    fprintf(o, "  %s-o%s %s<file.daxc>%s  %ssave full analysis snapshot%s  %s(symbols, CFG, xrefs, comments)%s\n", W, R, C, R, DG, R, DG, R);
    fprintf(o, "  %s-c%s              %sconvert .daxc → annotated .S assembly file%s\n", W, R, DG, R);
    fprintf(o, "\n");

    fprintf(o, "%s╔══════════════════════╗%s\n", DG, R);
    fprintf(o, "%s║  MISC                ║%s\n", DG, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", DG, R);
    fprintf(o, "  %s-n%s              %sno color output%s  %s(for piping / logging)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-v%s              %sverbose mode%s  %s(instruction count, section info)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-h%s              %sthis help page%s\n", W, R, DG, R);
    fprintf(o, "\n");

    fprintf(o, "%s  Examples%s\n", W, R);
    fprintf(o, "  %s──────────────────────────────────────────────────────%s\n", DG, R);
    fprintf(o, "  %s$%s dax %s./binary%s\n", G, R, G, R);
    fprintf(o, "  %s$%s dax %s-x%s %s./binary%s\n", G, R, Y, R, G, R);
    fprintf(o, "  %s$%s dax %s-x -o%s %sanalysis.daxc%s %s./binary%s\n", G, R, Y, R, C, R, G, R);
    fprintf(o, "  %s$%s dax %s-c%s %sanalysis.daxc%s                %s→ analysis.S%s\n", G, R, Y, R, C, R, DG, R);
    fprintf(o, "  %s$%s dax %s-i -x%s %s./binary%s                  %s→ interactive RE%s\n", G, R, Y, R, G, R, DG, R);
    fprintf(o, "  %s$%s dax %s-s .plt -a%s %s./binary%s              %s→ .plt with bytes%s\n", G, R, Y, R, G, R, DG, R);
    fprintf(o, "\n");
}

static void dax_header_line(int use_color) {
    int i;
    if (use_color) printf("%s", COL_SECTION);
    for (i = 0; i < DAX_BANNER_WIDTH; i++) printf("-");
    if (use_color) printf("%s", COL_RESET);
    printf("\n");
}

void dax_print_banner(dax_binary_t *bin, dax_opts_t *opts) {
    int color = opts ? opts->color : 1;

    printf("\n");
    dax_header_line(color);
    printf("%s"
        " ██████╗   █████╗ ██╗  ██╗\n"
        " ██╔══██╗ ██╔══██╗╚██╗██╔╝\n"
        " ██║  ██║ ███████║ ╚███╔╝ \n"
        " ██║  ██║ ██╔══██║ ██╔██╗ \n"
        " ██████╔╝ ██║  ██║██╔╝ ██╗\n"
        " ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝\n"
        "%s", color?COL_LABEL:"", color?COL_RESET:"");
    printf("%s  DAX v%s - Binary Analysis & Disassembler%s\n",
           color?COL_COMMENT:"", DAX_VERSION, color?COL_RESET:"");
    dax_header_line(color);

    printf(" %sFile%s      : %s\n",    color?COL_MNEM:"", color?COL_RESET:"", bin->filepath);
    printf(" %sFormat%s    : %s\n",    color?COL_MNEM:"", color?COL_RESET:"", dax_fmt_str(bin->fmt));
    printf(" %sArch%s      : %s\n",    color?COL_MNEM:"", color?COL_RESET:"", dax_arch_str(bin->arch));
    printf(" %sOS/ABI%s    : %s\n",    color?COL_MNEM:"", color?COL_RESET:"", dax_os_str(bin->os));
    printf(" %sEntry%s     : %s0x%016llx%s\n",
           color?COL_MNEM:"", color?COL_RESET:"",
           color?COL_ENTRY:"", (unsigned long long)bin->entry, color?COL_RESET:"");
    printf(" %sSections%s  : %d\n", color?COL_MNEM:"", color?COL_RESET:"", bin->nsections);
    if (bin->nsymbols)   printf(" %sSymbols%s   : %d\n",   color?COL_MNEM:"",color?COL_RESET:"",bin->nsymbols);
    if (bin->nfunctions) printf(" %sFunctions%s : %d\n",   color?COL_MNEM:"",color?COL_RESET:"",bin->nfunctions);
    if (bin->nblocks)    printf(" %sCFG Blocks%s: %d\n",   color?COL_MNEM:"",color?COL_RESET:"",bin->nblocks);
    if (bin->nxrefs)     printf(" %sXrefs%s     : %d\n",   color?COL_MNEM:"",color?COL_RESET:"",bin->nxrefs);
    if (bin->ncomments)  printf(" %sComments%s  : %d\n",   color?COL_MNEM:"",color?COL_RESET:"",bin->ncomments);

    dax_header_line(color);
    printf("\n");
}

void dax_print_sections(dax_binary_t *bin, dax_opts_t *opts) {
    int c = opts ? opts->color : 1;
    int i;
    static const char *stlabel[] = {
        "code","data","rodata","bss","plt","got","dyn","dbg","other"
    };
    extern const char *dax_sec_type_color(dax_sec_type_t t, int color);

    printf("\n");
    if (c) printf("%s", COL_MNEM);
    printf("  %-22s %-10s %-18s %-18s %-12s %s\n",
           "Section","Type","VirtAddr","Offset","Size","Flags");
    if (c) printf("%s", COL_RESET);
    if (c) printf("%s", COL_COMMENT);
    { int j; for(j=0;j<100;j++) printf("─"); }
    if (c) printf("%s", COL_RESET);
    printf("\n");

    for (i = 0; i < bin->nsections; i++) {
        dax_section_t *s  = &bin->sections[i];
        const char    *tc = c ? dax_sec_type_color(s->type, 1) : "";
        const char    *rc = c ? COL_RESET : "";
        const char    *ac = c ? COL_ADDR  : "";
        printf("  %s%-22s%s %s%-10s%s %s0x%016llx%s  0x%016llx  %-12llu",
               tc, s->name, rc, tc, stlabel[s->type], rc,
               ac, (unsigned long long)s->vaddr, rc,
               (unsigned long long)s->offset, (unsigned long long)s->size);
        if (s->flags) {
            if (c) printf("%s", COL_COMMENT);
            printf("  [%s%s%s]",
                   (s->flags&0x4||s->flags&0x20000000) ? "x" : "",
                   (s->flags&0x2) ? "w" : "",
                   (s->flags&0x1) ? "r" : "");
            if (c) printf("%s", COL_RESET);
        }
        printf("\n");
    }
    printf("\n");
}

const char *dax_arch_str(dax_arch_t a) {
    switch(a){ case ARCH_X86_64: return "x86_64"; case ARCH_ARM64: return "AArch64 (ARM64)"; case ARCH_RISCV64: return "RISC-V RV64GC"; default: return "unknown"; }
}
const char *dax_fmt_str(dax_fmt_t f) {
    switch(f){ case FMT_ELF32: return "ELF32"; case FMT_ELF64: return "ELF64"; case FMT_PE32: return "PE32"; case FMT_PE64: return "PE64+"; case FMT_RAW: return "Raw"; default: return "unknown"; }
}
const char *dax_os_str(dax_os_t o) {
    switch(o){ case DAX_PLAT_LINUX: return "Linux"; case DAX_PLAT_ANDROID: return "Android"; case DAX_PLAT_BSD: return "BSD/macOS"; case DAX_PLAT_UNIX: return "UNIX/SysV"; case DAX_PLAT_WINDOWS: return "Windows"; default: return "unknown"; }
}

int main(int argc, char **argv) {
    dax_binary_t bin;
    dax_opts_t   opts;
    int          list_only  = 0;
    int          to_asm     = 0;
    int          is_daxc    = 0;
    int          i;
    const char  *filepath   = NULL;

    dax_print_correction(argc, argv, stderr);

    memset(&bin,  0, sizeof(bin));
    memset(&opts, 0, sizeof(opts));
    opts.show_addr  = 1;
    opts.color      = 1;
    opts.start_addr = 0;
    opts.end_addr   = (uint64_t)-1;
    strncpy(opts.section, ".text", sizeof(opts.section)-1);

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'a': opts.show_bytes   = 1; break;
                case 'n': opts.color        = 0; break;
                case 'v': opts.verbose      = 1; break;
                case 'l': list_only         = 1; break;
                case 'S': opts.all_sections = 1; break;
                case 'y': opts.symbols      = 1; break;
                case 'd': opts.demangle     = 1; break;
                case 'f': opts.funcs        = 1; break;
                case 'g': opts.groups       = 1; break;
                case 'r': opts.xrefs        = 1; break;
                case 't': opts.strings      = 1; break;
                case 'C': opts.cfg          = 1; break;
                case 'L': opts.loops        = 1; break;
                case 'G': opts.callgraph    = 1; break;
                case 'W': opts.switches     = 1; break;
                case 'i': opts.interactive  = 1; break;
                case 'c': to_asm            = 1; break;
                case 'x':
                    opts.symbols = opts.demangle = opts.funcs = 1;
                    opts.groups  = opts.xrefs = opts.strings = opts.cfg = 1;
                    opts.loops   = opts.callgraph = opts.switches = 1;
                    break;
                case 'h': print_usage(); return 0;
                case 's':
                    if (i+1 < argc) strncpy(opts.section, argv[++i], sizeof(opts.section)-1);
                    break;
                case 'A':
                    if (i+1 < argc) opts.start_addr = (uint64_t)strtoull(argv[++i],NULL,16);
                    break;
                case 'E':
                    if (i+1 < argc) opts.end_addr = (uint64_t)strtoull(argv[++i],NULL,16);
                    break;
                case 'o':
                    if (i+1 < argc) strncpy(opts.output_daxc, argv[++i], 511);
                    break;
                default:
                    fprintf(stderr, "dax: unknown option '-%c'\n", argv[i][1]);
                    print_usage(); return 1;
            }
        } else {
            filepath = argv[i];
        }
    }

    if (!filepath) {
        fprintf(stderr, "dax: no input file\n");
        print_usage(); return 1;
    }

    {
        size_t flen = strlen(filepath);
        if (flen > 5 && strcmp(filepath + flen - 5, ".daxc") == 0)
            is_daxc = 1;
    }

    if (is_daxc && to_asm) {
        char asm_path[520];
        size_t flen = strlen(filepath);
        strncpy(asm_path, filepath, 514);
        asm_path[flen - 5] = 0;
        strcat(asm_path, ".S");
        return dax_daxc_to_asm(filepath, asm_path, opts.color);
    }

    if (is_daxc) {
        if (dax_daxc_read(filepath, &bin) != 0) {
            fprintf(stderr, "dax: failed to read '%s'\n", filepath);
            return 1;
        }
        dax_print_banner(&bin, &opts);
        if (list_only) { dax_print_sections(&bin, &opts); dax_free_binary(&bin); return 0; }
        if (opts.interactive) {
            int r = dax_interactive(&bin, &opts);
            dax_free_binary(&bin);
            return r;
        }
        if (bin.arch == ARCH_X86_64)
            dax_disasm_x86_64(&bin, &opts, stdout);
        else if (bin.arch == ARCH_ARM64)
            dax_disasm_arm64(&bin, &opts, stdout);
        else if (bin.arch == ARCH_RISCV64)
            dax_disasm_riscv64(&bin, &opts, stdout);
        dax_free_binary(&bin);
        return 0;
    }

    if (dax_load_binary(filepath, &bin) != 0) {
        fprintf(stderr, "dax: failed to load '%s'\n", filepath);
        return 1;
    }

    if (opts.callgraph) opts.xrefs = 1;
    if (opts.loops)     opts.cfg   = 1;

    if (opts.symbols || opts.funcs || opts.xrefs || opts.strings || opts.cfg || opts.interactive) {
        dax_sym_load(&bin);
        if (opts.xrefs || opts.cfg)
            dax_xref_build(&bin);
    }

    if ((opts.cfg || opts.loops) && !opts.interactive) {
        int si, fi;
        for (si = 0; si < bin.nsections; si++) {
            if (bin.sections[si].type == SEC_TYPE_CODE && bin.sections[si].size > 0) {
                uint8_t *code = bin.data + bin.sections[si].offset;
                size_t   sz   = (size_t)bin.sections[si].size;
                uint64_t base = bin.sections[si].vaddr;
                dax_func_detect(&bin, code, sz, base, &bin.sections[si]);
            }
        }
        for (fi = 0; fi < bin.nfunctions; fi++) {
            dax_func_t *fn = &bin.functions[fi];
            int si2;
            for (si2 = 0; si2 < bin.nsections; si2++) {
                dax_section_t *sec = &bin.sections[si2];
                if (fn->start >= sec->vaddr && fn->start < sec->vaddr + sec->size &&
                    sec->offset + sec->size <= bin.size) {
                    uint8_t *code = bin.data + sec->offset;
                    size_t   sz   = (size_t)sec->size;
                    uint64_t base = sec->vaddr;
                    dax_cfg_build(&bin, code, sz, base, fi);
                    break;
                }
            }
        }
    }

    dax_print_banner(&bin, &opts);

    if (list_only) {
        dax_print_sections(&bin, &opts);
        if (opts.output_daxc[0]) dax_daxc_write(&bin, &opts, opts.output_daxc);
        dax_free_binary(&bin);
        return 0;
    }

    if (opts.interactive) {
        if (!bin.nfunctions && (opts.funcs || opts.symbols)) {
            int si;
            for (si = 0; si < bin.nsections; si++) {
                if (bin.sections[si].type == SEC_TYPE_CODE) {
                    uint8_t *code = bin.data + bin.sections[si].offset;
                    size_t   sz   = (size_t)bin.sections[si].size;
                    uint64_t base = bin.sections[si].vaddr;
                    dax_func_detect(&bin, code, sz, base, &bin.sections[si]);
                }
            }
        }
        {
            int r = dax_interactive(&bin, &opts);
            if (opts.output_daxc[0]) dax_daxc_write(&bin, &opts, opts.output_daxc);
            dax_free_binary(&bin);
            return r;
        }
    }

    if (bin.arch == ARCH_X86_64)
        dax_disasm_x86_64(&bin, &opts, stdout);
    else if (bin.arch == ARCH_ARM64)
        dax_disasm_arm64(&bin, &opts, stdout);
    else if (bin.arch == ARCH_RISCV64)
        dax_disasm_riscv64(&bin, &opts, stdout);
    else {
        fprintf(stderr, "dax: unsupported architecture\n");
        dax_free_binary(&bin); return 1;
    }

    if (opts.cfg) {
        int fi;
        printf("\n");
        if (opts.color) printf("%s", COL_FUNC);
        printf("  ══════════════ CONTROL FLOW GRAPHS ══════════════\n");
        if (opts.color) printf("%s", COL_RESET);
        for (fi = 0; fi < bin.nfunctions; fi++)
            dax_cfg_print(&bin, fi, &opts, stdout);
    }

    if (opts.loops)
        dax_loop_print_all(&bin, &opts, stdout);

    if (opts.callgraph)
        dax_callgraph_print(&bin, &opts, stdout);

    if (opts.switches) {
        int si;
        int c = opts.color;
        printf("\n");
        if (c) printf("%s", COL_FUNC);
        printf("  ══════════════ SWITCH DETECTION ══════════════\n");
        if (c) printf("%s", COL_RESET);
        for (si = 0; si < bin.nsections; si++) {
            if (bin.sections[si].type == SEC_TYPE_CODE &&
                bin.sections[si].size > 0 &&
                bin.sections[si].offset + bin.sections[si].size <= bin.size) {
                uint8_t *code = bin.data + bin.sections[si].offset;
                size_t   sz   = (size_t)bin.sections[si].size;
                uint64_t base = bin.sections[si].vaddr;
                if (c) printf("%s  [%s]%s\n", COL_SECTION, bin.sections[si].name, COL_RESET);
                dax_switch_detect(&bin, &opts, code, sz, base, stdout);
            }
        }
        printf("\n");
    }

    if (opts.output_daxc[0])
        dax_daxc_write(&bin, &opts, opts.output_daxc);

    dax_free_binary(&bin);
    return 0;
}

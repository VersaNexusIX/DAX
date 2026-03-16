#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#if defined(_WIN32) || defined(_WIN64)
  #include <windows.h>
  #include <conio.h>
  #define TERM_WINDOWS 1
#else
  #include <termios.h>
  #include <unistd.h>
  #include <sys/ioctl.h>
  #define TERM_UNIX 1
#endif

#include "dax.h"
#include "x86.h"
#include "arm64.h"

extern dax_igrp_t  dax_classify_x86(const char *m);
extern dax_igrp_t  dax_classify_arm64(const char *m);
extern const char *dax_igrp_color(dax_igrp_t g, int color);
extern int         dax_cfg_print(dax_binary_t *bin, int func_idx,
                                  dax_opts_t *opts, FILE *out);
extern int         dax_daxc_write(dax_binary_t *bin, dax_opts_t *opts, const char *path);

#define MAX_VIEW_INSNS  65536
#define STATUS_HEIGHT   2
#define HELP_HEIGHT     1
#define MIN_ROWS        8

typedef struct {
    uint64_t  addr;
    char      mnemonic[DAX_MAX_MNEMONIC];
    char      operands[DAX_MAX_OPERANDS];
    uint8_t   bytes[DAX_MAX_INSN_LEN];
    uint8_t   len;
    uint8_t   grp;
} view_insn_t;

typedef struct {
    dax_binary_t  *bin;
    dax_opts_t    *opts;
    view_insn_t   *insns;
    int            ninsns;
    int            cursor;
    int            top;
    int            rows;
    int            cols;
    char           search[128];
    char           status[256];
    int            mode;
    int            section_idx;
    int            show_help;
    int            show_cfg;
    int            dirty;
    char           rename_buf[DAX_SYM_NAME_LEN];
    char           comment_buf[DAX_COMMENT_LEN];
} ire_state_t;

#define MODE_NORMAL  0
#define MODE_SEARCH  1
#define MODE_GOTO    2
#define MODE_RENAME  3
#define MODE_COMMENT 4
#define MODE_SAVE    5

static void term_clear(void) { printf("\033[2J\033[H"); fflush(stdout); }
static void term_goto(int r, int c) { printf("\033[%d;%dH", r, c); fflush(stdout); }
static void term_hide_cursor(void)  { printf("\033[?25l"); fflush(stdout); }
static void term_show_cursor(void)  { printf("\033[?25h"); fflush(stdout); }
static void term_color(const char *c) { printf("%s", c); }
static void term_reset(void) { printf("%s", COL_RESET); }

#ifdef TERM_UNIX
static struct termios g_old_term;

static void term_raw(void) {
    struct termios t;
    tcgetattr(STDIN_FILENO, &g_old_term);
    t = g_old_term;
    t.c_lflag &= ~(ICANON | ECHO);
    t.c_cc[VMIN]  = 1;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

static void term_restore(void) {
    tcsetattr(STDIN_FILENO, TCSANOW, &g_old_term);
}

static void term_size(int *rows, int *cols) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *rows = ws.ws_row;
        *cols = ws.ws_col;
    } else {
        *rows = 24; *cols = 80;
    }
}

static int term_read_key(void) {
    unsigned char buf[4] = {0};
    if (read(STDIN_FILENO, buf, 1) != 1) return -1;
    if (buf[0] == 0x1b) {
        int n = (int)read(STDIN_FILENO, buf + 1, 3);
        if (n >= 2 && buf[1] == '[') {
            if (buf[2] == 'A') return 1000;
            if (buf[2] == 'B') return 1001;
            if (buf[2] == 'C') return 1002;
            if (buf[2] == 'D') return 1003;
            if (buf[2] == '5' && n >= 3 && buf[3] == '~') return 1004;
            if (buf[2] == '6' && n >= 3 && buf[3] == '~') return 1005;
            if (buf[2] == 'H') return 1006;
            if (buf[2] == 'F') return 1007;
        }
        return 0x1b;
    }
    return (int)buf[0];
}
#else
static void term_raw(void) {}
static void term_restore(void) {}
static void term_size(int *rows, int *cols) { *rows = 25; *cols = 80; }
static int  term_read_key(void) { return _getch(); }
#endif

#define KEY_UP      1000
#define KEY_DOWN    1001
#define KEY_RIGHT   1002
#define KEY_LEFT    1003
#define KEY_PGUP    1004
#define KEY_PGDN    1005
#define KEY_HOME    1006
#define KEY_END     1007
#define KEY_ESC     0x1b
#define KEY_ENTER   '\r'
#define KEY_CTRL(x) ((x) & 0x1f)

static int collect_section_insns(ire_state_t *st, int sec_idx) {
    dax_binary_t  *bin = st->bin;
    dax_section_t *sec;
    uint8_t       *code;
    size_t         sz;
    uint64_t       base;
    size_t         off = 0;
    int            count = 0;

    if (sec_idx < 0 || sec_idx >= bin->nsections) return -1;
    sec  = &bin->sections[sec_idx];
    if (sec->offset + sec->size > bin->size) return -1;
    code = bin->data + sec->offset;
    sz   = (size_t)sec->size;
    base = sec->vaddr;

    if (!st->insns) {
        st->insns  = (view_insn_t *)calloc(MAX_VIEW_INSNS, sizeof(view_insn_t));
        if (!st->insns) return -1;
    }
    st->ninsns = 0;

    if (bin->arch == ARCH_X86_64) {
        while (off < sz && st->ninsns < MAX_VIEW_INSNS) {
            x86_insn_t insn;
            int l = x86_decode(code + off, sz - off, base + off, &insn);
            if (l <= 0) { off++; continue; }
            st->insns[count].addr = base + off;
            strncpy(st->insns[count].mnemonic, insn.mnemonic, DAX_MAX_MNEMONIC-1);
            strncpy(st->insns[count].operands, insn.ops, DAX_MAX_OPERANDS-1);
            memcpy(st->insns[count].bytes, code + off, l < DAX_MAX_INSN_LEN ? (size_t)l : DAX_MAX_INSN_LEN);
            st->insns[count].len = (uint8_t)l;
            st->insns[count].grp = (uint8_t)dax_classify_x86(insn.mnemonic);
            count++;
            off += (size_t)l;
        }
    } else {
        while (off + 4 <= sz && st->ninsns < MAX_VIEW_INSNS) {
            uint32_t   raw = (uint32_t)(code[off])|(code[off+1]<<8)|(code[off+2]<<16)|(code[off+3]<<24);
            a64_insn_t insn;
            a64_decode(raw, base + off, &insn);
            st->insns[count].addr = base + off;
            strncpy(st->insns[count].mnemonic, insn.mnemonic, DAX_MAX_MNEMONIC-1);
            strncpy(st->insns[count].operands, insn.operands, DAX_MAX_OPERANDS-1);
            memcpy(st->insns[count].bytes, code + off, 4);
            st->insns[count].len = 4;
            st->insns[count].grp = (uint8_t)dax_classify_arm64(insn.mnemonic);
            count++;
            off += 4;
        }
    }

    st->ninsns = count;
    st->cursor = 0;
    st->top    = 0;
    return count;
}

static void draw_titlebar(ire_state_t *st) {
    int  i;
    char title[256];
    int  tlen;
    dax_binary_t *bin = st->bin;

    snprintf(title, sizeof(title),
             " DAX v%s  │  %s  │  %s  │  %s  │  %d syms  │  %d funcs ",
             DAX_VERSION, bin->filepath,
             dax_arch_str(bin->arch), dax_fmt_str(bin->fmt),
             bin->nsymbols, bin->nfunctions);

    term_goto(1, 1);
    term_color("\033[1;37;44m");
    tlen = (int)strlen(title);
    printf("%s", title);
    for (i = tlen; i < st->cols; i++) putchar(' ');
    term_reset();
}

static void draw_statusbar(ire_state_t *st) {
    char  left[256], right[256];
    int   ll, rl, pad;
    view_insn_t *cur_insn = (st->ninsns > 0 && st->cursor < st->ninsns)
                             ? &st->insns[st->cursor] : NULL;

    if (st->mode == MODE_SEARCH) {
        snprintf(left, sizeof(left), " /search: %s_", st->search);
    } else if (st->mode == MODE_GOTO) {
        snprintf(left, sizeof(left), " :goto 0x%s_", st->search);
    } else if (st->mode == MODE_RENAME) {
        snprintf(left, sizeof(left), " rename: %s_", st->rename_buf);
    } else if (st->mode == MODE_COMMENT) {
        snprintf(left, sizeof(left), " comment: %s_", st->comment_buf);
    } else if (st->mode == MODE_SAVE) {
        snprintf(left, sizeof(left), " save as: %s_", st->rename_buf);
    } else if (st->status[0]) {
        snprintf(left, sizeof(left), " %s", st->status);
    } else {
        if (cur_insn) {
            dax_symbol_t *sym = dax_sym_find(st->bin, cur_insn->addr);
            const char *sn = sym ? (sym->demangled[0] ? sym->demangled : sym->name) : "";
            snprintf(left, sizeof(left),
                     " 0x%016llx  %-10s %-28s  %s",
                     (unsigned long long)cur_insn->addr,
                     cur_insn->mnemonic, cur_insn->operands, sn);
        } else {
            snprintf(left, sizeof(left), " [no instruction]");
        }
    }

    snprintf(right, sizeof(right), " [%d/%d]  %s ",
             st->cursor + 1, st->ninsns,
             st->bin->sections[st->section_idx < st->bin->nsections
                                ? st->section_idx : 0].name);

    ll  = (int)strlen(left);
    rl  = (int)strlen(right);
    pad = st->cols - ll - rl;
    if (pad < 0) pad = 0;

    term_goto(st->rows + STATUS_HEIGHT - 1, 1);
    term_color("\033[0;37;40m");
    printf("%s", left);
    { int i; for (i = 0; i < pad; i++) putchar(' '); }
    printf("%s", right);
    term_reset();
}

static void draw_helpbar(ire_state_t *st) {
    term_goto(st->rows + STATUS_HEIGHT, 1);
    term_color(COL_COMMENT);
    printf(" hjkl/arrows:nav  /:search  g:goto  n:next-func  r:rename  c:comment  "
           "C:cfg  o:output  q:quit  ?:help");
    { int i = 80; while(i++ < st->cols) putchar(' '); }
    term_reset();
}

static void draw_insn_line(ire_state_t *st, int row, int vidx, int is_cursor) {
    view_insn_t  *ins = &st->insns[vidx];
    dax_symbol_t *sym = dax_sym_find(st->bin, ins->addr);
    const char   *cmt = dax_comment_get(st->bin, ins->addr);
    dax_func_t   *fn  = dax_func_find(st->bin, ins->addr);
    int           c   = st->opts->color;

    term_goto(row, 1);

    if (fn && fn->start == ins->addr) {
        const char *fname = fn->name;
        if (c) term_color(COL_FUNC);
        printf("  ┄ %s (%llu bytes) ", fname,
               (unsigned long long)(fn->end > fn->start ? fn->end - fn->start : 0));
        term_reset();
        printf("\n");
        term_goto(row + 1, 1);
    }

    if (sym && sym->address == ins->addr) {
        if (is_cursor) { term_color(COL_HILIGHT); }
        else if (c) { term_color(sym->is_entry ? COL_ENTRY : COL_LABEL); }
        printf("  %s:", sym->demangled[0] ? sym->demangled : sym->name);
        term_reset();
        printf("\n");
        term_goto(row + 2, 1);
    }

    if (is_cursor) term_color(COL_HILIGHT);

    if (c && !is_cursor) term_color(COL_ADDR);
    printf("  %016llx  ", (unsigned long long)ins->addr);
    if (c && !is_cursor) term_reset();

    if (st->opts->show_bytes) {
        char bs[40] = "";
        int  bi;
        for (bi = 0; bi < ins->len && bi < 8; bi++)
            sprintf(bs + bi*3, "%02x ", ins->bytes[bi]);
        if (c && !is_cursor) term_color(COL_BYTES);
        printf("%-25s", bs);
        if (c && !is_cursor) term_reset();
    }

    {
        const char *mcol = (c && !is_cursor) ? dax_igrp_color((dax_igrp_t)ins->grp, 1) : "";
        const char *ocol = (c && !is_cursor) ? COL_OPS : "";
        const char *rst  = (c && !is_cursor) ? COL_RESET : "";
        printf("%s%-10s%s %-30s%s", mcol, ins->mnemonic, rst, ins->operands, rst);
    }

    if (cmt) {
        if (c && !is_cursor) term_color(COL_STRING);
        printf("  ; %s", cmt);
        if (c && !is_cursor) term_reset();
    }

    { int i = 60; while (i++ < st->cols - 2) putchar(' '); }

    if (is_cursor) term_reset();
    putchar('\n');
}

static void draw_view(ire_state_t *st) {
    int view_rows = st->rows - STATUS_HEIGHT - HELP_HEIGHT;
    int row = 2;
    int i;

    if (view_rows < MIN_ROWS) view_rows = MIN_ROWS;

    for (i = 0; i < view_rows && (st->top + i) < st->ninsns; i++) {
        draw_insn_line(st, row + i, st->top + i, (st->top + i) == st->cursor);
    }

    for (; i < view_rows; i++) {
        term_goto(row + i, 1);
        { int j; for (j = 0; j < st->cols; j++) putchar(' '); }
    }
}

static void ire_redraw(ire_state_t *st) {
    term_size(&st->rows, &st->cols);
    term_clear();
    term_hide_cursor();
    draw_titlebar(st);
    draw_view(st);
    draw_statusbar(st);
    draw_helpbar(st);
    fflush(stdout);
}

static void ire_scroll_to_cursor(ire_state_t *st) {
    int view_rows = st->rows - STATUS_HEIGHT - HELP_HEIGHT - 1;
    if (view_rows < 1) view_rows = 1;
    if (st->cursor < st->top) st->top = st->cursor;
    if (st->cursor >= st->top + view_rows) st->top = st->cursor - view_rows + 1;
    if (st->top < 0) st->top = 0;
}

static int ire_find_next(ire_state_t *st, int from, const char *query, int wrap) {
    int i;
    for (i = from; i < st->ninsns; i++) {
        if (strstr(st->insns[i].mnemonic, query) ||
            strstr(st->insns[i].operands, query)) return i;
    }
    if (wrap) {
        for (i = 0; i < from; i++) {
            if (strstr(st->insns[i].mnemonic, query) ||
                strstr(st->insns[i].operands, query)) return i;
        }
    }
    return -1;
}

static int ire_find_by_addr(ire_state_t *st, uint64_t addr) {
    int i;
    for (i = 0; i < st->ninsns; i++)
        if (st->insns[i].addr == addr) return i;
    for (i = 0; i < st->ninsns - 1; i++)
        if (addr >= st->insns[i].addr && addr < st->insns[i+1].addr) return i;
    return -1;
}

static int ire_next_func(ire_state_t *st) {
    int i;
    dax_binary_t *bin = st->bin;
    for (i = st->cursor + 1; i < st->ninsns; i++) {
        dax_func_t *fn = dax_func_find(bin, st->insns[i].addr);
        if (fn && fn->start == st->insns[i].addr) return i;
    }
    return -1;
}

static int ire_prev_func(ire_state_t *st) {
    int i;
    dax_binary_t *bin = st->bin;
    for (i = st->cursor - 1; i >= 0; i--) {
        dax_func_t *fn = dax_func_find(bin, st->insns[i].addr);
        if (fn && fn->start == st->insns[i].addr) return i;
    }
    return -1;
}

static void show_help_popup(ire_state_t *st) {
    int rows, cols;
    int i;
    term_size(&rows, &cols);
    term_clear();

    const char *BG   = "\033[48;5;235m";
    const char *BG2  = "\033[48;5;237m";
    const char *RST  = "\033[0m";
    const char *KEY  = "\033[1;33;48;5;235m";
    const char *DESC = "\033[0;37;48;5;235m";
    const char *SEP  = "\033[0;90;48;5;235m";
    const char *HEAD = "\033[1;36;48;5;237m";
    const char *LOGO = "\033[1;34m";
    const char *VER  = "\033[0;90m";
    const char *HINT = "\033[0;32m";

    printf("\n");
    printf("%s  ██████╗   █████╗ ██╗  ██╗%s\n", LOGO, RST);
    printf("%s  ██╔══██╗ ██╔══██╗╚██╗██╔╝%s  %sInteractive RE Mode%s\n", LOGO, RST, VER, RST);
    printf("%s  ██║  ██║ ███████║ ╚███╔╝ %s  %sv%s%s\n", LOGO, RST, VER, DAX_VERSION, RST);
    printf("%s  ██║  ██║ ██╔══██║ ██╔██╗ %s\n", LOGO, RST);
    printf("%s  ██████╔╝ ██║  ██║██╔╝ ██╗%s\n", LOGO, RST);
    printf("%s  ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝%s\n", LOGO, RST);
    printf("\n");

    struct { const char *key; const char *desc; int is_head; } entries[] = {
        {"NAVIGATION",            "",                            1},
        {"j / ↓",                 "scroll down one instruction", 0},
        {"k / ↑",                 "scroll up one instruction",   0},
        {"J / PgDn",              "scroll down one page",        0},
        {"K / PgUp",              "scroll up one page",          0},
        {"g / Home",              "jump to first instruction",   0},
        {"G / End",               "jump to last instruction",    0},
        {"n",                     "jump to next function",       0},
        {"p",                     "jump to previous function",   0},
        {"SEARCH & GOTO",         "",                            1},
        {"/",                     "search by mnemonic or operand",0},
        {".",                     "repeat last search forward",  0},
        {":",                     "goto address (hex input)",    0},
        {"ANNOTATIONS",           "",                            1},
        {"r",                     "rename symbol at cursor",     0},
        {"c",                     "add or edit comment",         0},
        {"VIEW",                  "",                            1},
        {"a",                     "toggle hex bytes display",    0},
        {"s",                     "switch to another section",   0},
        {"C",                     "show CFG for current function",0},
        {"FILES",                 "",                            1},
        {"o",                     "save session as .daxc file",  0},
        {"OTHER",                 "",                            1},
        {"q / ESC",               "quit  (prompts save if dirty)",0},
        {"? / h",                 "show this help screen",       0},
        {NULL, NULL, 0}
    };

    for (i = 0; entries[i].key; i++) {
        if (entries[i].is_head) {
            printf("%s  %-18s%s\n", HEAD,
                   entries[i].key, RST);
            printf("%s  ", SEP);
            { int j; for(j=0;j<56;j++) printf("─"); }
            printf("%s\n", RST);
        } else {
            printf("%s  %-16s%s  %s%s%s\n",
                   KEY, entries[i].key, RST,
                   DESC, entries[i].desc, RST);
        }
    }

    printf("\n");
    printf("%s  ╭─────────────────────────────────────────────────────╮%s\n", SEP, RST);
    printf("%s  │%s  %sTIP%s  combine %s-x -i%s for full analysis in TUI mode    %s│%s\n",
           SEP, RST, HINT, RST, KEY, RST, SEP, RST);
    printf("%s  │%s  %sTIP%s  press %so%s to snapshot analysis → %s.daxc%s file     %s│%s\n",
           SEP, RST, HINT, RST, KEY, RST, KEY, RST, SEP, RST);
    printf("%s  ╰─────────────────────────────────────────────────────╯%s\n", SEP, RST);
    printf("\n");
    printf("%s  press any key to return ...%s\n", VER, RST);
    fflush(stdout);
    term_read_key();
    (void)BG; (void)BG2; (void)rows; (void)cols;
}

static void show_cfg_popup(ire_state_t *st) {
    view_insn_t  *cur = (st->cursor < st->ninsns) ? &st->insns[st->cursor] : NULL;
    dax_func_t   *fn  = cur ? dax_func_find(st->bin, cur->addr) : NULL;
    int           fi  = fn ? (int)(fn - st->bin->functions) : -1;

    term_clear();
    if (fi >= 0) {
        dax_cfg_print(st->bin, fi, st->opts, stdout);
        printf("\n  Press any key...\n");
    } else {
        printf("  No function at 0x%016llx\n  Press any key...\n",
               (unsigned long long)(cur ? cur->addr : 0));
    }
    fflush(stdout);
    term_read_key();
}

static void section_picker(ire_state_t *st) {
    int i, key;
    term_clear();
    term_color(COL_FUNC);
    printf("\n  Select section to disassemble:\n\n");
    term_reset();
    for (i = 0; i < st->bin->nsections; i++) {
        dax_section_t *sec = &st->bin->sections[i];
        if (sec->type == SEC_TYPE_CODE || sec->type == SEC_TYPE_PLT) {
            term_color(COL_ADDR);
            printf("  [%2d] ", i);
            term_reset();
            printf("%-24s  0x%016llx  %llu bytes\n",
                   sec->name, (unsigned long long)sec->vaddr,
                   (unsigned long long)sec->size);
        }
    }
    printf("\n  Enter section number: ");
    fflush(stdout);
    {
        char buf[8] = "";
        int  bi = 0;
        while ((key = term_read_key()) != '\n' && key != KEY_ENTER) {
            if (key == KEY_ESC) return;
            if (isdigit(key) && bi < 7) { buf[bi++] = (char)key; putchar(key); }
        }
        buf[bi] = 0;
        if (bi > 0) {
            int idx = atoi(buf);
            if (idx >= 0 && idx < st->bin->nsections) {
                st->section_idx = idx;
                collect_section_insns(st, idx);
                snprintf(st->status, sizeof(st->status),
                         "Switched to section %s",
                         st->bin->sections[idx].name);
            }
        }
    }
}

int dax_interactive(dax_binary_t *bin, dax_opts_t *opts) {
    ire_state_t st;
    int         key;
    int         running = 1;
    int         sec_idx = 0;
    int         i;

    memset(&st, 0, sizeof(st));
    st.bin   = bin;
    st.opts  = opts;
    st.mode  = MODE_NORMAL;

    for (i = 0; i < bin->nsections; i++) {
        if (bin->sections[i].type == SEC_TYPE_CODE) { sec_idx = i; break; }
    }
    st.section_idx = sec_idx;

    collect_section_insns(&st, sec_idx);
    if (st.ninsns == 0) {
        fprintf(stderr, "dax: no instructions to display in interactive mode\n");
        return -1;
    }

    term_raw();
    term_clear();
    term_hide_cursor();

    ire_redraw(&st);

    while (running) {
        key = term_read_key();

        switch (st.mode) {
        case MODE_SEARCH:
        case MODE_GOTO: {
            char *buf = (st.mode == MODE_SEARCH) ? st.search : st.search;
            int  *len = NULL;
            int   blen = (int)strlen(buf);
            if (key == KEY_ENTER || key == '\r' || key == '\n') {
                if (st.mode == MODE_SEARCH) {
                    int found = ire_find_next(&st, st.cursor + 1, st.search, 1);
                    if (found >= 0) {
                        st.cursor = found;
                        ire_scroll_to_cursor(&st);
                        snprintf(st.status, sizeof(st.status),
                                 "Found '%s' at 0x%llx", st.search,
                                 (unsigned long long)st.insns[found].addr);
                    } else {
                        snprintf(st.status, sizeof(st.status),
                                 "Not found: '%s'", st.search);
                    }
                } else {
                    uint64_t addr = (uint64_t)strtoull(st.search, NULL, 16);
                    int found = ire_find_by_addr(&st, addr);
                    if (found >= 0) {
                        st.cursor = found;
                        ire_scroll_to_cursor(&st);
                        snprintf(st.status, sizeof(st.status),
                                 "Jumped to 0x%llx", (unsigned long long)addr);
                    } else {
                        snprintf(st.status, sizeof(st.status),
                                 "Address 0x%llx not in view", (unsigned long long)addr);
                    }
                }
                st.mode = MODE_NORMAL;
            } else if (key == KEY_ESC) {
                st.mode = MODE_NORMAL; st.status[0] = 0;
            } else if (key == 127 || key == 8) {
                if (blen > 0) buf[blen - 1] = 0;
            } else if (isprint(key) && blen < 127) {
                buf[blen++] = (char)key; buf[blen] = 0;
            }
            (void)len;
            break;
        }
        case MODE_RENAME: {
            int blen = (int)strlen(st.rename_buf);
            if (key == KEY_ENTER || key == '\r') {
                if (blen > 0 && st.cursor < st.ninsns) {
                    uint64_t addr = st.insns[st.cursor].addr;
                    dax_symbol_t *sym = dax_sym_find(bin, addr);
                    if (sym) {
                        strncpy(sym->name, st.rename_buf, DAX_SYM_NAME_LEN-1);
                        strncpy(sym->demangled, st.rename_buf, DAX_SYM_NAME_LEN-1);
                    }
                    dax_func_t *fn = dax_func_find(bin, addr);
                    if (fn && fn->start == addr)
                        strncpy(fn->name, st.rename_buf, DAX_SYM_NAME_LEN-1);
                    snprintf(st.status, sizeof(st.status),
                             "Renamed to '%s'", st.rename_buf);
                    st.dirty = 1;
                }
                st.mode = MODE_NORMAL;
            } else if (key == KEY_ESC) {
                st.mode = MODE_NORMAL; st.status[0] = 0;
            } else if (key == 127 || key == 8) {
                if (blen > 0) st.rename_buf[blen - 1] = 0;
            } else if (isprint(key) && blen < DAX_SYM_NAME_LEN-1) {
                st.rename_buf[blen++] = (char)key; st.rename_buf[blen] = 0;
            }
            break;
        }
        case MODE_COMMENT: {
            int blen = (int)strlen(st.comment_buf);
            if (key == KEY_ENTER || key == '\r') {
                if (st.cursor < st.ninsns) {
                    dax_comment_add(bin, st.insns[st.cursor].addr, st.comment_buf);
                    snprintf(st.status, sizeof(st.status),
                             "Comment added at 0x%llx",
                             (unsigned long long)st.insns[st.cursor].addr);
                    st.dirty = 1;
                }
                st.mode = MODE_NORMAL;
            } else if (key == KEY_ESC) {
                st.mode = MODE_NORMAL; st.status[0] = 0;
            } else if (key == 127 || key == 8) {
                if (blen > 0) st.comment_buf[blen - 1] = 0;
            } else if (isprint(key) && blen < DAX_COMMENT_LEN-1) {
                st.comment_buf[blen++] = (char)key; st.comment_buf[blen] = 0;
            }
            break;
        }
        case MODE_SAVE: {
            int blen = (int)strlen(st.rename_buf);
            if (key == KEY_ENTER || key == '\r') {
                if (blen > 0) {
                    dax_daxc_write(bin, opts, st.rename_buf);
                    snprintf(st.status, sizeof(st.status),
                             "Saved: %s", st.rename_buf);
                    st.dirty = 0;
                }
                st.mode = MODE_NORMAL;
            } else if (key == KEY_ESC) {
                st.mode = MODE_NORMAL; st.status[0] = 0;
            } else if (key == 127 || key == 8) {
                if (blen > 0) st.rename_buf[blen - 1] = 0;
            } else if (isprint(key) && blen < 511) {
                st.rename_buf[blen++] = (char)key; st.rename_buf[blen] = 0;
            }
            break;
        }
        default: {
            int view_rows = st.rows - STATUS_HEIGHT - HELP_HEIGHT - 1;
            if (view_rows < 1) view_rows = 1;
            switch (key) {
                case 'q': case 'Q': case KEY_ESC:
                    if (st.dirty) {
                        st.mode = MODE_SAVE;
                        snprintf(st.rename_buf, sizeof(st.rename_buf), "out.daxc");
                        snprintf(st.status, sizeof(st.status),
                                 "Unsaved changes. Save as (.daxc): ");
                    } else {
                        running = 0;
                    }
                    break;
                case 'j': case KEY_DOWN:
                    if (st.cursor < st.ninsns - 1) {
                        st.cursor++;
                        ire_scroll_to_cursor(&st);
                        st.status[0] = 0;
                    }
                    break;
                case 'k': case KEY_UP:
                    if (st.cursor > 0) {
                        st.cursor--;
                        ire_scroll_to_cursor(&st);
                        st.status[0] = 0;
                    }
                    break;
                case 'J': case KEY_PGDN:
                    st.cursor = st.cursor + view_rows;
                    if (st.cursor >= st.ninsns) st.cursor = st.ninsns - 1;
                    ire_scroll_to_cursor(&st);
                    st.status[0] = 0;
                    break;
                case 'K': case KEY_PGUP:
                    st.cursor = st.cursor - view_rows;
                    if (st.cursor < 0) st.cursor = 0;
                    ire_scroll_to_cursor(&st);
                    st.status[0] = 0;
                    break;
                case 'g': case KEY_HOME:
                    st.cursor = 0; st.top = 0; st.status[0] = 0; break;
                case 'G': case KEY_END:
                    st.cursor = st.ninsns - 1;
                    ire_scroll_to_cursor(&st);
                    st.status[0] = 0;
                    break;
                case 'n':
                    { int ni = ire_next_func(&st);
                      if (ni >= 0) { st.cursor = ni; ire_scroll_to_cursor(&st);
                          snprintf(st.status, sizeof(st.status), "Next function");
                      } else snprintf(st.status, sizeof(st.status), "No more functions"); }
                    break;
                case 'p':
                    { int ni = ire_prev_func(&st);
                      if (ni >= 0) { st.cursor = ni; ire_scroll_to_cursor(&st);
                          snprintf(st.status, sizeof(st.status), "Prev function");
                      } else snprintf(st.status, sizeof(st.status), "No previous function"); }
                    break;
                case '/':
                    st.mode = MODE_SEARCH; st.search[0] = 0; st.status[0] = 0; break;
                case '.':
                    if (st.search[0]) {
                        int found = ire_find_next(&st, st.cursor + 1, st.search, 1);
                        if (found >= 0) { st.cursor = found; ire_scroll_to_cursor(&st);
                            snprintf(st.status, sizeof(st.status), "Found '%s'", st.search);
                        } else snprintf(st.status, sizeof(st.status), "Not found: '%s'", st.search);
                    }
                    break;
                case ':':
                    st.mode = MODE_GOTO; st.search[0] = 0; st.status[0] = 0; break;
                case 'r':
                    { dax_symbol_t *sym = (st.cursor < st.ninsns)
                          ? dax_sym_find(bin, st.insns[st.cursor].addr) : NULL;
                      strncpy(st.rename_buf, sym ?
                          (sym->demangled[0] ? sym->demangled : sym->name) : "", DAX_SYM_NAME_LEN-1);
                      st.mode = MODE_RENAME; }
                    break;
                case 'c':
                    { const char *existing = (st.cursor < st.ninsns)
                          ? dax_comment_get(bin, st.insns[st.cursor].addr) : NULL;
                      strncpy(st.comment_buf, existing ? existing : "", DAX_COMMENT_LEN-1);
                      st.mode = MODE_COMMENT; }
                    break;
                case 'a':
                    st.opts->show_bytes = !st.opts->show_bytes;
                    snprintf(st.status, sizeof(st.status),
                             "Bytes %s", st.opts->show_bytes ? "ON" : "OFF");
                    break;
                case 'C':
                    show_cfg_popup(&st); break;
                case 'o':
                    st.mode = MODE_SAVE;
                    snprintf(st.rename_buf, sizeof(st.rename_buf), "out.daxc");
                    snprintf(st.status, sizeof(st.status), "Save as (.daxc): ");
                    break;
                case 's':
                    section_picker(&st); break;
                case '?': case 'h':
                    show_help_popup(&st); break;
                case KEY_CTRL('l'):
                    break;
            }
        }
        }
        ire_redraw(&st);
    }

    term_show_cursor();
    term_restore();
    term_clear();

    if (st.insns) free(st.insns);
    return 0;
}

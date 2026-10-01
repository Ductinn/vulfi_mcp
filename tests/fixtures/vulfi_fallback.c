/* Fixture binary for the Ghidra fallback provider: evidence a Ghidra
 * auto-analysis leaves on the table, and call sites whose arguments are
 * provable from P-code alone.
 *
 * Built by the `compiled_fallback` fixture with
 * `gcc -O0 -fno-builtin -fno-inline -fPIE -pie`, so every call below survives
 * as its own call site with its own recoverable argument, and the pointers in
 * `.vulfi_fb_ptrs` really do carry relocations.
 *
 * Shapes, and what each one is here to pin:
 *
 *   .vulfi_fb_blob      Bytes nothing references, in a section Ghidra's string
 *                       analyzer does not type. The run opens with bytes that
 *                       are not text in any encoding, then a NUL-terminated
 *                       ASCII marker. The marker is recovered from mapped
 *                       bytes read at a cited address, never from a listing
 *                       that already named it.
 *
 *   .vulfi_fb_hidden    A valid stretch of code in an executable section with
 *                       no symbol and no call reaching it, so auto-analysis
 *                       creates no function over it. A relocated pointer in
 *                       .vulfi_fb_ptrs names its first byte, which is what
 *                       makes it *reachable* without being *marked*: the
 *                       cross-reference is the evidence, and the mapped bytes
 *                       are the proof that an entry really is there.
 *
 *   vulfi_fb_tail       A label inside `vulfi_fb_tail_owner` that the second
 *                       relocated pointer names: an entry overlapping a
 *                       function Ghidra already owns. Defining a function
 *                       there would redefine code that is not ours, so it has
 *                       to stay a candidate however good the pointer looks.
 *
 *   vulfi_fb_fmt_*      Two `printf` call sites that differ only in whether
 *                       the format argument is a constant. High P-code states
 *                       that difference directly — a constant varnode versus
 *                       one defined by a register load — so the stock
 *                       "Format String" rule can be evaluated from structure
 *                       alone.
 *
 *   vulfi_fb_copy_*     Two `strcpy` call sites whose source is a variable,
 *                       one of them guarded by a `strlen` on the same buffer.
 *                       The stock "Buffer Overflow" rule's High branch asks
 *                       `used_in_call_before(['strlen'])`, which no typed
 *                       Ghidra tool in this build states: the decompiled C
 *                       shows the guard, and reading it out of that text is
 *                       exactly what this adapter refuses to do. The rule is
 *                       therefore `unsupported` with a reason, never a guess.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ----------------------------------------------------------------------
 * Raw bytes nothing references.
 * ------------------------------------------------------------------- */
__asm__(
    ".section .vulfi_fb_blob,\"a\",@progbits\n"
    ".balign 16\n"
    /* Not text in any encoding, and first, so a head-of-section heuristic
     * has nothing to type. */
    "  .byte 0x8f,0x01,0xd3,0x02,0xa7,0x03,0xbe,0x04,0xc1,0x05,0xfa,0x06\n"
    ".balign 16\n"
    /* "vulfi-fallback-raw-marker", ASCII, NUL-terminated (26 bytes) */
    "  .byte 0x76,0x75,0x6c,0x66,0x69,0x2d,0x66,0x61,0x6c,0x6c,0x62,0x61\n"
    "  .byte 0x63,0x6b,0x2d,0x72,0x61,0x77,0x2d,0x6d,0x61,0x72,0x6b,0x65\n"
    "  .byte 0x72,0x00\n"
    ".balign 32\n"
    /* "vulfi-fb-utf16le", UTF-16LE, NUL-terminated (34 bytes) */
    "  .byte 0x76,0x00,0x75,0x00,0x6c,0x00,0x66,0x00,0x69,0x00,0x2d,0x00\n"
    "  .byte 0x66,0x00,0x62,0x00,0x2d,0x00,0x75,0x00,0x74,0x00,0x66,0x00\n"
    "  .byte 0x31,0x00,0x36,0x00,0x6c,0x00,0x65,0x00,0x00,0x00\n"
    ".balign 32\n"
    /* "vulfi-fb-utf16be", UTF-16BE, NUL-terminated (34 bytes) */
    "  .byte 0x00,0x76,0x00,0x75,0x00,0x6c,0x00,0x66,0x00,0x69,0x00,0x2d\n"
    "  .byte 0x00,0x66,0x00,0x62,0x00,0x2d,0x00,0x75,0x00,0x74,0x00,0x66\n"
    "  .byte 0x00,0x31,0x00,0x36,0x00,0x62,0x00,0x65,0x00,0x00\n"
    ".previous\n");

/* A function whose middle the second relocated pointer names. */
int vulfi_fb_tail_owner(int value)
{
    int total = value + 1;

    __asm__ volatile(".globl vulfi_fb_tail\nvulfi_fb_tail:");
    total += 3;
    return total;
}

/* ----------------------------------------------------------------------
 * One unreferenced stretch of code in its own executable section. No
 * symbol, no call: only the relocated pointer below points at it.
 * ------------------------------------------------------------------- */
__asm__(
    ".section .vulfi_fb_hidden,\"ax\",@progbits\n"
    ".balign 16\n"
    "  endbr64\n"
    "  mov %edi,%eax\n"
    "  add $0x2a,%eax\n"
    "  ret\n"
    ".previous\n");

/* One relocated pointer at the unmarked entry, one into the tail above. */
__asm__(
    ".section .vulfi_fb_ptrs,\"aw\",@progbits\n"
    ".balign 8\n"
    ".globl vulfi_fb_pointer_table\n"
    "vulfi_fb_pointer_table:\n"
    "  .quad .vulfi_fb_hidden\n"
    "  .quad vulfi_fb_tail\n"
    ".previous\n");

extern int (*vulfi_fb_pointer_table[2])(int value);

/* ----------------------------------------------------------------------
 * Format-string call sites: one constant, one not.
 * ------------------------------------------------------------------- */

/* The format argument is a literal: a constant varnode at the call. */
void vulfi_fb_fmt_constant(void)
{
    printf("vulfi-fallback-constant-format\n");
}

/* The format argument comes from the environment: not a constant. */
void vulfi_fb_fmt_variable(void)
{
    const char *fmt = getenv("VULFI_FALLBACK_FORMAT");

    if (fmt != NULL) {
        printf(fmt, 1);
    }
}

/* ----------------------------------------------------------------------
 * Buffer-copy call sites whose source is a variable either way. Only the
 * guard differs, and the guard is the fact no typed tool here states.
 * ------------------------------------------------------------------- */

/* Unguarded: nothing measures `input` before it is copied. */
void vulfi_fb_copy_unguarded(const char *input)
{
    char local[32];

    strcpy(local, input);
    puts(local);
}

/* Guarded: `strlen` takes the same buffer before the copy does. */
void vulfi_fb_copy_guarded(const char *input)
{
    char local[32];

    if (strlen(input) < sizeof(local)) {
        strcpy(local, input);
        puts(local);
    }
}

int main(int argc, char **argv)
{
    vulfi_fb_fmt_constant();
    vulfi_fb_fmt_variable();
    if (argc > 1) {
        vulfi_fb_copy_unguarded(argv[1]);
        vulfi_fb_copy_guarded(argv[1]);
    }
    printf("%d\n", vulfi_fb_tail_owner(argc));
    return 0;
}

/* Fixture binary for VulFi preparation: code and strings a plain IDA
 * auto-analysis leaves behind.
 *
 * Built with `gcc -O0 -fno-inline -fPIE -pie`, so the buffer in
 * `vulfi_stack_string` really is assembled out of immediate operands instead
 * of copied from `.rodata`, and the pointer below really does carry a
 * relocation.
 *
 * Shapes, and what each one is here to pin:
 *
 *   .vulfi_blob         Bytes nothing references. The section opens with a
 *                       run that is not text in any encoding, which is what
 *                       keeps IDA's own string pass — it types the head of a
 *                       data section and nothing after it — away from the
 *                       three strings that follow: ASCII, UTF-16LE and
 *                       UTF-16BE, each NUL-terminated, each left undefined.
 *
 *   .vulfi_hidden       Three valid stretches of code in an executable
 *                       section that nothing calls, so IDA decodes the bytes
 *                       and creates no function over any of them. The first
 *                       carries a local ELF symbol and is the one
 *                       preparation may define; the second carries nothing
 *                       at all; the third branches out of itself to an
 *                       address that is not a function entry, and the block
 *                       its own conditional branch targets must stay a
 *                       candidate because the only thing reaching it is a
 *                       jump from inside unrecognized code.
 *
 *   vulfi_overlap_tail  A label *inside* `vulfi_tail_owner` that a relocated
 *                       pointer names: a call target overlapping an existing
 *                       function, which must stay a candidate rather than
 *                       redefine code IDA already owns.
 *
 *   vulfi_stack_string  A buffer written one immediate at a time, so its
 *                       bytes exist only in the instructions that build it.
 */

#include <stdio.h>

/* ----------------------------------------------------------------------
 * Raw bytes in three encodings, with nothing referencing any of them.
 * ------------------------------------------------------------------- */
__asm__(
    ".section .vulfi_blob,\"a\",@progbits\n"
    ".balign 16\n"
    /* Not text in any encoding, and first so that IDA's head-of-section
     * string heuristic has nothing to type. */
    "  .byte 0x8f,0x01,0xd3,0x02,0xa7,0x03,0xbe,0x04,0xc1,0x05,0xfa,0x06\n"
    ".balign 16\n"
    /* "vulfi-plain-ascii-marker", ASCII, NUL-terminated (25 bytes) */
    "  .byte 0x76,0x75,0x6c,0x66,0x69,0x2d,0x70,0x6c,0x61,0x69,0x6e,0x2d\n"
    "  .byte 0x61,0x73,0x63,0x69,0x69,0x2d,0x6d,0x61,0x72,0x6b,0x65,0x72\n"
    "  .byte 0x00\n"
    ".balign 16\n"
    /* "vulfi-utf16le", UTF-16LE, NUL-terminated (28 bytes) */
    "  .byte 0x76,0x00,0x75,0x00,0x6c,0x00,0x66,0x00,0x69,0x00,0x2d,0x00\n"
    "  .byte 0x75,0x00,0x74,0x00,0x66,0x00,0x31,0x00,0x36,0x00,0x6c,0x00\n"
    "  .byte 0x65,0x00,0x00,0x00\n"
    ".balign 16\n"
    /* "vulfi-utf16be", UTF-16BE, NUL-terminated (28 bytes) */
    "  .byte 0x00,0x76,0x00,0x75,0x00,0x6c,0x00,0x66,0x00,0x69,0x00,0x2d\n"
    "  .byte 0x00,0x75,0x00,0x74,0x00,0x66,0x00,0x31,0x00,0x36,0x00,0x62\n"
    "  .byte 0x00,0x65,0x00,0x00\n"
    ".previous\n");

/* ----------------------------------------------------------------------
 * Three unreferenced stretches in their own executable section.
 * ------------------------------------------------------------------- */
__asm__(
    ".section .vulfi_hidden,\"ax\",@progbits\n"
    ".balign 16\n"
    /* A local ELF symbol, no relocation, no call: IDA names the address and
     * leaves it outside every function. */
    "vulfi_hidden_add:\n"
    "  endbr64\n"
    "  mov %edi,%eax\n"
    "  add $0x2a,%eax\n"
    "  ret\n"
    ".balign 16\n"
    /* No symbol, no relocation, no call: nothing says this is an entry
     * point, so preparation may describe it and may not define it. */
    "  endbr64\n"
    "  mov %esi,%eax\n"
    "  sub $0x11,%eax\n"
    "  ret\n"
    ".balign 16\n"
    /* A third stretch whose own linear decode refuses — it branches out of
     * the stretch to an address that is not a function entry — while the
     * block its conditional branch targets decodes cleanly to a return.
     * The only thing pointing at that block is a jump from inside this same
     * undefined stretch, which is ordinary control flow inside something
     * unrecognized and not an entry point: preparation must describe that
     * block and must never define a function over it. */
    "  endbr64\n"
    "  test %edi,%edi\n"
    "  je 1f\n"
    "  jmp vulfi_overlap_tail\n"
    "1:\n"
    "  mov %edi,%eax\n"
    "  ret\n"
    ".previous\n");

/* A function whose middle a relocated pointer names. */
int vulfi_tail_owner(int value)
{
    int total = value + 1;

    __asm__ volatile(".globl vulfi_overlap_tail\nvulfi_overlap_tail:");
    total += 3;
    return total;
}

/* One relocated pointer at a real entry, one into the tail above. */
__asm__(
    ".section .vulfi_ptrs,\"aw\",@progbits\n"
    ".balign 8\n"
    ".globl vulfi_pointer_table\n"
    "vulfi_pointer_table:\n"
    "  .quad vulfi_tail_owner\n"
    "  .quad vulfi_overlap_tail\n"
    ".previous\n");

extern int (*vulfi_pointer_table[2])(int value);

/* A buffer assembled out of immediate operands, never stored in .rodata. */
void vulfi_stack_string(void)
{
    char marker[24] = "vulfi-stack-string!!";

    puts(marker);
}

int main(int argc, char **argv)
{
    (void)argv;
    vulfi_stack_string();
    printf("%d %d\n", vulfi_pointer_table[0](argc), vulfi_tail_owner(argc));
    return 0;
}

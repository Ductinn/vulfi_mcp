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
 *
 *   vulfi_consistent_record
 *                       A global object every access reaches at the same
 *                       offset with the same width, so a layout can be
 *                       proven from the instructions that use it.
 *
 *   vulfi_conflicting_record
 *                       The same object read four bytes wide and eight bytes
 *                       wide at offset zero. A layout cannot be both, so the
 *                       disagreement is reported and nothing is defined.
 *
 *   vulfi_stride_table  Four accesses at one width, eight bytes apart: an
 *                       array stride rather than a set of distinct fields.
 *
 *   .vulfi_fnptrs       Three relocated pointers, every target a function
 *                       entry: a pointer table with a relocation record
 *                       behind every slot.
 *
 *   .vulfi_ints         The same width and the same alignment as the table
 *                       above, and — with this image loaded at zero — every
 *                       value a 16-byte-aligned address in its own code,
 *                       starting with `_init`. They are assembled out of
 *                       plain integers, so no relocation record exists. IDA
 *                       marks these as offsets on its own; preparation must
 *                       still refuse to define a table over them.
 *
 *   .vulfi_ragged       One relocated pointer at a four-byte offset inside a
 *                       section whose length is not a whole number of
 *                       pointers: bad alignment and a truncated tail, both
 *                       of which have to be named rather than skipped.
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

/* ----------------------------------------------------------------------
 * Global objects whose layout exists only in the instructions that use
 * them. Every access below is a direct, sized operand, so IDA records a
 * read or a write cross-reference at the exact byte it touches.
 * ------------------------------------------------------------------- */
struct vulfi_record {
    int  count;   /* +0,  4 bytes */
    int  limit;   /* +4,  4 bytes */
    long total;   /* +8,  8 bytes */
};

union vulfi_overlapped {
    struct vulfi_record record;
    long whole;   /* +0, 8 bytes: overlaps count and limit */
};

struct vulfi_record vulfi_consistent_record;
union vulfi_overlapped vulfi_conflicting_record;
long vulfi_stride_table[4];

int vulfi_record_read(void)
{
    return vulfi_consistent_record.count + vulfi_consistent_record.limit;
}

long vulfi_record_total(void)
{
    return vulfi_consistent_record.total;
}

void vulfi_record_write(int value)
{
    vulfi_consistent_record.count = value;
    vulfi_consistent_record.limit = value + 1;
    vulfi_consistent_record.total = value + 2;
}

int vulfi_conflicting_narrow(void)
{
    return vulfi_conflicting_record.record.count
         + vulfi_conflicting_record.record.limit;
}

long vulfi_conflicting_wide(void)
{
    return vulfi_conflicting_record.whole
         + vulfi_conflicting_record.record.total;
}

long vulfi_stride_sum(void)
{
    return vulfi_stride_table[0] + vulfi_stride_table[1]
         + vulfi_stride_table[2] + vulfi_stride_table[3];
}

/* ----------------------------------------------------------------------
 * Three pointer-shaped ranges that differ only in what backs them.
 * ------------------------------------------------------------------- */

/* Every slot carries an R_X86_64_RELATIVE relocation and every target is a
 * function entry. */
__asm__(
    ".section .vulfi_fnptrs,\"aw\",@progbits\n"
    ".balign 8\n"
    ".globl vulfi_function_table\n"
    "vulfi_function_table:\n"
    "  .quad vulfi_record_read\n"
    "  .quad vulfi_record_total\n"
    "  .quad vulfi_record_write\n"
    ".previous\n");

/* The same width and the same alignment as the table above, and with this
 * image loaded at zero every value is a 16-byte-aligned address in its own
 * code: `_init` at 0x1000, then PLT stubs. Nothing relocates them, because
 * they are plain integers, which is the only thing that sets this range
 * apart from the one above. */
__asm__(
    ".section .vulfi_ints,\"aw\",@progbits\n"
    ".balign 8\n"
    ".globl vulfi_integer_table\n"
    "vulfi_integer_table:\n"
    "  .quad 0x1000\n"
    "  .quad 0x1020\n"
    "  .quad 0x1030\n"
    "  .quad 0x1040\n"
    ".previous\n");

/* A relocated pointer four bytes into an eight-byte grid, and seventeen
 * bytes of section: the last slot cannot be read whole. */
__asm__(
    ".section .vulfi_ragged,\"aw\",@progbits\n"
    ".balign 16\n"
    "  .byte 0,0,0,0\n"
    ".globl vulfi_misaligned_pointer\n"
    "vulfi_misaligned_pointer:\n"
    "  .quad vulfi_record_read\n"
    "  .byte 0,0,0,0,0\n"
    ".previous\n");

int main(int argc, char **argv)
{
    (void)argv;
    vulfi_stack_string();
    printf("%d %d\n", vulfi_pointer_table[0](argc), vulfi_tail_owner(argc));
    return 0;
}

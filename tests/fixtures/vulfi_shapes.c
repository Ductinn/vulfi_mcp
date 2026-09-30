/* Fixture binary for the VulFi MCP wrapper, array, and loop evidence tests.
 *
 * Compiled with `gcc -O0 -fno-builtin -fno-inline`, so every shape below
 * survives into the decompiled ctree the scan reads its facts from. The
 * arrays are locals on purpose: without debug information IDA types a pointer
 * parameter as an integer, and Hex-Rays then emits pointer arithmetic instead
 * of the indexing expression the array and loop rules look for.
 *
 * Shapes, and the upstream VulFi behaviour each one pins:
 *   release_buffer()  free(buffer)            -> one-level wrapper discovery
 *   drop_buffer()     release_buffer(buffer)  -> the call the wrapper reports
 *   lstrcpya()        a name with a pinned prototype and no type in the IDB
 *   read_table()      table[index]            -> array index, signed-compared
 *   copy_dynamic()    for (i; i < count; )    -> loop with a variable bound
 *   fill_fixed()      for (i; i < 8; )        -> loop with a constant bound
 *   reset_state()     reset_state()           -> a verified zero-argument call
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_state;

/* Every argument of the inner call is an argument of this function, which is
 * exactly the shape one-level wrapper discovery looks for. */
void release_buffer(char *buffer)
{
    free(buffer);
}

/* Calls the wrapper and never clears the pointer, so the wrapped rule matches
 * and the call to the wrapper is the site that gets reported. */
void drop_buffer(void)
{
    char *buffer = malloc(64);

    release_buffer(buffer);
    puts("dropped");
}

/* IDA recognizes this name and VulFi ships a prototype for it, but the
 * database has no type for it, so the scan has to apply that prototype before
 * it can recover this call's arguments. */
void lstrcpya(char *destination, const char *source)
{
    strcpy(destination, source);
}

/* The index reaches a signed comparison in the enclosing `if`, and is then
 * used to index memory. */
int read_table(int index)
{
    int table[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    int total = 0;

    if (index > 4) {
        total += table[index];
        total += table[index - 1];
    }
    return total;
}

/* Loop bounded by a variable, whose counter indexes memory. */
void copy_dynamic(const char *source, int count)
{
    char destination[32];
    int i;

    for (i = 0; i < count; i++)
        destination[i] = source[i];
    destination[31] = 0;
    puts(destination);
}

/* Loop bounded by a constant, whose counter indexes memory. */
void fill_fixed(void)
{
    char destination[32];
    int i;

    for (i = 0; i < 8; i++)
        destination[i] = 'A';
    destination[8] = 0;
    puts(destination);
}

/* A call site whose argument list really is empty. */
void reset_state(void)
{
    g_state = 0;
}

int main(int argc, char **argv)
{
    char destination[64];

    drop_buffer();
    copy_dynamic(argv[0], argc);
    fill_fixed();
    reset_state();
    lstrcpya(destination, argv[0]);
    printf("%d %d %s\n", g_state, read_table(argc), destination);
    return 0;
}

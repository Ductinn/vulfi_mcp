/* Fixture binary for the VulFi MCP IDA tests.
 *
 * Compiled by the `compiled_calls` fixture with
 * `gcc -O0 -fno-builtin -fno-inline`, so every call below survives as its own
 * call site with its own recoverable argument.
 *
 * Call sites, in the order a scan meets them:
 *   copy_from_argument()    strcpy(local, input)    -> variable source
 *   copy_from_environment() strcpy(local, value)    -> variable source
 *   copy_constant()         strcpy(g_buffer, "...") -> constant source
 *
 * The two variable-source `strcpy` calls are what a `mark_if` branch such as
 * `param(2).is_variable()` must report; the constant-source call is the
 * negative that the same branch must leave alone.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_buffer[64];

/* Variable source #1: the copied bytes come straight from the caller. */
void copy_from_argument(const char *input)
{
    char local[32];

    strcpy(local, input);
    puts(local);
}

/* Variable source #2: the copied bytes come from the environment. */
void copy_from_environment(void)
{
    char local[32];
    const char *value = getenv("VULFI_FIXTURE_INPUT");

    if (value != NULL) {
        strcpy(local, value);
        puts(local);
    }
}

/* Constant source: nothing untrusted reaches this call site. */
void copy_constant(void)
{
    strcpy(g_buffer, "vulfi-constant");
    puts(g_buffer);
}

/* A wrapper, so rules that follow wrappers have something to follow. */
void copy_wrapper(const char *input)
{
    copy_from_argument(input);
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        copy_from_argument(argv[1]);
        copy_wrapper(argv[1]);
    }
    copy_from_environment();
    copy_constant();
    return 0;
}

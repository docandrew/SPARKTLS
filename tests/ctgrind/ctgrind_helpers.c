/* C shim around Valgrind client requests for ctgrind-style
 * constant-time analysis of Ada code.
 *
 * VALGRIND_MAKE_MEM_UNDEFINED expands to an inline asm sequence
 * that's awkward to embed directly in Ada inline asm — we wrap it
 * in plain C functions and call from Ada via Interfaces.C.
 *
 * Usage from Ada side: mark secret data (keys, scalars, etc.) as
 * "undefined" before calling crypto primitives. Run the resulting
 * binary under "valgrind --tool=memcheck". Any branch or memory
 * access whose target depends on the secret will raise "use of
 * uninitialised value" — that's the ctgrind constant-time signal.
 */

#include <stddef.h>
#include <valgrind/memcheck.h>

void ctgrind_make_undefined(void *addr, size_t size)
{
    VALGRIND_MAKE_MEM_UNDEFINED(addr, size);
}

void ctgrind_make_defined(void *addr, size_t size)
{
    VALGRIND_MAKE_MEM_DEFINED(addr, size);
}

/* Force the compiler to materialise a value so it's not eliminated
 * as dead code. Without this, the back-end may notice that the
 * crypto output is never read and skip the whole thing. */
void ctgrind_use(const void *addr, size_t size)
{
    asm volatile("" :: "r"(addr), "r"(size) : "memory");
}

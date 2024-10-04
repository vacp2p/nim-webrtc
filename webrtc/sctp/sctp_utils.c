#include <stdio.h>
#include <stdarg.h>

void sctpPrintf(const char *fmt, ...) {
	va_list args;
    va_start(args, fmt);        // Initialize the argument list
    vprintf(fmt, args);         // Call vprintf with the argument list
    va_end(args);               // Clean up
}

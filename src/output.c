#include <stdio.h>
#include <string.h>
#include <time.h>
#include "output.h"

#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#endif

void init_colors(void) {
#ifdef _WIN32
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(console, &mode)) {
        SetConsoleMode(console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif
}

static const char *color_code(const char *color) {
    if (strcmp(color, "red") == 0) return "\033[1;31m";
    if (strcmp(color, "green") == 0) return "\033[1;32m";
    if (strcmp(color, "yellow") == 0) return "\033[1;33m";
    if (strcmp(color, "blue") == 0) return "\033[1;34m";
    if (strcmp(color, "magenta") == 0) return "\033[1;35m";
    if (strcmp(color, "cyan") == 0) return "\033[1;36m";
    if (strcmp(color, "gray") == 0) return "\033[0;90m";
    return "\033[1;37m";
}

void echo(const char *text, const char *color) {
    printf("%s%s\033[0m", color_code(color), text);
}

void echo_padded(const char *text, const char *color, int width) {
    int pad = width - (int)strlen(text);
    echo(text, color);
    while (pad-- > 0) printf(" ");
}

void print_title(const char *title) {
    printf("\n");
    echo("[+] ", "blue");
    echo(title, "blue");
    echo(" [+]\n", "blue");
}

void print_time(unsigned int timestamp) {
    time_t value = (time_t)timestamp;
    struct tm *utc = gmtime(&value);
    char buffer[64];

    if (utc == NULL) {
        printf("Invalid time (0x%08X)\n", timestamp);
        return;
    }
    strftime(buffer, sizeof(buffer), "%A %Y-%m-%d %H:%M:%S UTC", utc);
    printf("%s\n", buffer);
}

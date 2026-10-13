#ifndef OUTPUT_H
#define OUTPUT_H

void init_colors(void);
void echo(const char *text, const char *color);
void echo_padded(const char *text, const char *color, int width);
void print_title(const char *title);
void print_time(unsigned int timestamp);

#endif


#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>

extern int errors;

void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *str);

void error(const char *file, int line, const char *msg);
void fatal(const char *msg);
void syserr(const char *msg);
void error_msg(const char *msg1, const char *msg2);

#endif /* UTILS_H */

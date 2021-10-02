
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

#define PROG_NAME "asm"
#define MAX_ERRORS 1000

int errors = 0;

void *xmalloc(size_t size)
{
  void *ptr;
  if ((ptr = malloc(size)) == 0)
    {
      syserr("cannot allocate memory");
    }
  return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
  if ((ptr = realloc(ptr, size)) == 0)
    {
      syserr("cannot reallocate memory");
    }
  return ptr;
}

char *xstrdup(const char *str)
{
  char *str2 = strdup(str);
  if (str2 == NULL)
    {
      syserr("cannot allocate memory");
    }
  return str2;
}

void error(const char *file, int line, const char *msg)
{
  fprintf(stderr, "%s:%d: Error: %s\n", file, line, msg);
  errors++;
  if (errors > MAX_ERRORS)
    {
      fatal("Too many errors.");
    }
}

void fatal(const char *msg)
{
  fprintf(stderr, "%s: Fatal error: %s\n", PROG_NAME, msg);
  exit(-1);
}

void syserr(const char *msg)
{
  perror(msg);
  exit(-1);
}

void error_msg(const char *msg1, const char *msg2)
{
  fprintf(stderr, "%s: Error: %s %s\n", PROG_NAME, msg1, msg2);
}


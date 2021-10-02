#include <libgen.h>
#include <string.h>
#include <stdio.h>

#include "utils.h"
#include "parser.h"
#include "translator.h"

int main(int argc, char **argv)
{
  char *str;
  int i, success;

  if (argc != 2)
    {
      str = xstrdup(argv[0]);
      fprintf(stderr, "Usage: %s program.asm\n", basename(str));
      free(str);
      return -1;
    }

  str = xstrdup(argv[1]);
  i = strlen(str);
  if (i < 4 || str[i - 1] != 'm' || str[i - 2] != 's' ||
      str[i - 3] != 'a' || str[i - 4] != '.')
    {
      free(str);
      str = xstrdup(argv[0]);
      fprintf(stderr, "Usage: %s program.asm\n", basename(str));
      free(str);
      return -1;
    }
  str[i - 3] = 'o';
  str[i - 2] = '\0';

  parser_init();
  translator_init();

  success = translate(argv[1], str);

  parser_cleanup();

  free(str);

  if (success)
    {
      return 0;
    }
  else
    {
      return 1;
    }
}

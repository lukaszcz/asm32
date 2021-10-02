
#include <search.h>
#include <stdlib.h>

#include "limits.h"
#include "utils.h"
#include "symtab.h"

void symtab_init()
{
  hcreate(SYMTAB_SIZE);
}

void symtab_cleanup()
{
  hdestroy();
}

void symtab_insert(const char *key, entry_t *entry)
{
  ENTRY e;
  e.key = (char*) key;
  e.data = entry;
  if (hsearch(e, FIND) != NULL)
    {
      error_msg("duplicate identifier:", key);
      return;
    }
  if (hsearch(e, ENTER) == NULL)
    {
      fatal("Symbol table full.");
    }
}

entry_t *symtab_search(const char *key)
{
  ENTRY e;
  ENTRY *pe;
  e.key = (char*) key;
  if ((pe = hsearch(e, FIND)) == NULL)
    {
      return NULL;
    }
  return (entry_t*) pe->data;
}


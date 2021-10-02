#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "limits.h"
#include "utils.h"
#include "symtab.h"
#include "parser.h"

static instr_t *pool_instr;
static arg_t *pool_arg;
static FILE *file;
static char *file_name;

static arg_t *new_arg(arg_t *arg);

/************************************************/

arg_t *new_arg(arg_t *arg)
{
  arg_t *np;

  if (pool_arg != NULL)
    {
      np = pool_arg->next;
      pool_arg->next = arg;
      arg = pool_arg;
      pool_arg = np;
    }
  else
    {
      np = arg;
      arg = (arg_t*) xmalloc(sizeof(arg_t));
      arg->next = np;
    }
  arg->type = ARG_NONE;
  return arg;
}

/************************************************/

int linenum;

void parser_init()
{
  pool_instr = NULL;
  pool_arg = NULL;
  file = NULL;
  linenum = 0;
  file_name = NULL;
}

void parser_cleanup()
{
  arg_t *np;
  if (pool_instr != NULL)
    {
      free(pool_instr);
    }
  while (pool_arg != NULL)
    {
      np = pool_arg->next;
      free(pool_arg);
      pool_arg = np;
    }
  if (file != NULL)
    {
      fclose(file);
    }
  if (file_name != NULL)
    {
      free(file_name);
    }
}

void open_file(const char *path)
{
  if (file != NULL)
    {
      if (fclose(file) == EOF)
        {
          syserr("cannot close file");
        }
    }
  if ((file = fopen(path, "r")) == NULL)
    {
      syserr("cannot open file");
    }
  if (file_name != NULL)
    {
      free(file_name);
    }
  file_name = xstrdup(path);
  linenum = 0;
  errors = 0;
}

instr_t *get_instr()
{
  instr_t *instr;
  entry_t *entry;
  char line[MAX_LINE_LEN];
  char str[MAX_STR_LEN];
  arg_t *stack[MAX_ARGS];
  int i, top, j, modifier, was_comma;
  arg_t *la;

  assert (file != NULL);

  for (;;)
    {
      ++linenum;
      if (fgets(line, MAX_LINE_LEN, file) != NULL)
        {
          i = 0;
          while (isspace(line[i]))
            {
              ++i;
            }
          if (line[i] == ';' || line[i] == '\0')
            {
              continue;
            }

          /* allocate the instr_t structure */
          if (pool_instr != NULL)
            {
              instr = pool_instr;
              pool_instr = NULL;
            }
          else
            {
              instr = (instr_t*) xmalloc(sizeof(instr_t));
            }
          instr->arg = NULL;
          instr->label[MAX_LABEL_LEN - 1] = '\0';
          instr->label[0] = '\0';
          instr->opcode = OP_NONE;

          if (!(isalpha(line[i]) || line[i] == '_'))
            {
              error(file_name, linenum, "Expected label or instruction.");
            }
          j = 0;
          while ((isalnum(line[i]) || line[i] == '_'))
            {
              str[j++] = line[i++];
            }
          str[j] = '\0';
          if (line[i] == ':')
            { /* a label */
              strncpy(instr->label, str, MAX_LABEL_LEN - 1);

              ++i;
              while (isspace(line[i]))
                {
                  ++i;
                }
              if (line[i] == ';' || line[i] == '\0')
                {
                  return instr;
                }
              /* read instruction opcode string */
              if (!(isalpha(line[i]) || line[i] == '_'))
                {
                  error(file_name, linenum, "Expected instruction.");
                }
              j = 0;
              while ((isalnum(line[i]) || line[i] == '_'))
                {
                  str[j++] = line[i++];
                }
              str[j] = '\0';
            }

          /* interpret instruction opcode */
          entry = symtab_search(str);
          if (entry == NULL || entry->type != SYM_OPCODE)
            {
              error(file_name, linenum, "Unknown instruction opcode.");
              return instr;
            }
          instr->opcode = entry->u.value;

          /* process instruction arguments */
          while (isspace(line[i]))
            {
              ++i;
            }

          if (line[i] != ';' && line[i] != '\0')
            {
              modifier = ARGMOD_NONE;
              was_comma = 1;
              while (line[i] != ';' && line[i] != '\0')
                {
                  while (isspace(line[i]))
                    {
                      ++i;
                    }

                  if (!was_comma)
                    {
                      error(file_name, linenum, "Expected a comma.");
                    }
                  /* read arguments */
                  if (isdigit(line[i]))
                    {
                      if (line[i + 1] == 'x')
                        {
                          i += 2;
                          if (!isxdigit(line[i]))
                            {
                              error(file_name, linenum, "Expected hexadecimal number.");
                            }
                          j = 0;
                          while (isxdigit(line[i]))
                            {
                              str[j++] = line[i++];
                            }
                          str[j] = '\0';
                          instr->arg = new_arg(instr->arg);
                          instr->arg->type = ARG_NUM;
                          instr->arg->u.value = strtol(str, NULL, 16);
                          instr->arg->modifier = modifier;
                        }
                      else
                        {
                          j = 0;
                          while (isdigit(line[i]))
                            {
                              str[j++] = line[i++];
                            }
                          str[j] = '\0';
                          instr->arg = new_arg(instr->arg);
                          instr->arg->type = ARG_NUM;
                          instr->arg->u.value = strtol(str, NULL, 0);
                          instr->arg->modifier = modifier;
                        }
                    }
                  else if (isalpha(line[i]) || line[i] == '_')
                    {
                      j = 0;
                      while ((isalnum(line[i]) || line[i] == '_'))
                        {
                          str[j++] = line[i++];
                        }
                      str[j] = '\0';
                      entry = symtab_search(str);
                      if (entry == NULL)
                        {
                          instr->arg = new_arg(instr->arg);
                          instr->arg->type = ARG_LABEL;
                          strncpy(instr->arg->u.label, str, MAX_LABEL_LEN - 1);
                          instr->arg->u.label[MAX_LABEL_LEN - 1] = '\0';
                          instr->arg->modifier = modifier;
                        }
                      else
                        {
                          switch(entry->type){
                          case SYM_REG32:
                            instr->arg = new_arg(instr->arg);
                            instr->arg->type = ARG_REG32;
                            instr->arg->u.reg = entry->u.value;
                            instr->arg->modifier = modifier;
                            break;
                          case SYM_REG8:
                            instr->arg = new_arg(instr->arg);
                            instr->arg->type = ARG_REG8;
                            instr->arg->u.reg = entry->u.value;
                            instr->arg->modifier = modifier;
                            break;
                          case SYM_ARGMOD:
                            modifier = entry->u.value;
                            was_comma = 1;
                            continue;
                          default:
                            instr->arg = new_arg(instr->arg);
                            instr->arg->type = ARG_LABEL;
                            strncpy(instr->arg->u.label, str, MAX_LABEL_LEN - 1);
                            instr->arg->u.label[MAX_LABEL_LEN - 1] = '\0';
                            instr->arg->modifier = modifier;
                            break;
                          };
                        }
                    }
                  else if (line[i] == '\'')
                    {
                      ++i;
                      j = 0;
                      while (line[i] != '\'')
                        {
                          if (line[i] == '\n')
                            {
                              error(file_name, linenum, "Expected closing apostrophe.");
                              break;
                            }
                          str[j++] = line[i++];
                        }
                      str[j] = '\0';
                      ++i;
                      instr->arg = new_arg(instr->arg);
                      instr->arg->modifier = modifier;
                      if (j == 1)
                        {
                          instr->arg->type = ARG_NUM;
                          instr->arg->u.value = str[0];
                        }
                      else
                        {
                          instr->arg->type = ARG_STR;
                          strncpy(instr->arg->u.str, str, MAX_STR_LEN - 1);
                          instr->arg->u.str[MAX_STR_LEN - 1] = '\0';
                        }
                    }
                  else if (line[i] == '.')
                    {
                      ++i;
                      j = 0;
                      while ((isalnum(line[i]) || line[i] == '_'))
                        {
                          str[j++] = line[i++];
                        }
                      str[j] = '\0';
                      instr->arg = new_arg(instr->arg);
                      instr->arg->type = ARG_DOT_IDENT;
                      strncpy(instr->arg->u.label, str, MAX_LABEL_LEN - 1);
                      instr->arg->u.label[MAX_LABEL_LEN - 1] = '\0';
                      instr->arg->modifier = modifier;
                    }
                  else if (line[i] == '[')
                    {
                      ++i;
                      while (isspace(line[i]))
                        {
                          ++i;
                        }
                      if (!(isalpha(line[i]) || line[i] == '_'))
                        {
                          error(file_name, linenum, "Expected register or label.");
                          continue;
                        }
                      j = 0;
                      while ((isalnum(line[i]) || line[i] == '_'))
                        {
                          str[j++] = line[i++];
                        }
                      str[j] = '\0';
                      instr->arg = new_arg(instr->arg);
                      instr->arg->modifier = modifier;
                      entry = symtab_search(str);
                      if (entry == NULL)
                        {
                          instr->arg->type = ARG_ADDR_LABEL;
                          strncpy(instr->arg->u.label, str, MAX_LABEL_LEN - 1);
                          instr->arg->u.label[MAX_LABEL_LEN - 1] = '\0';
                        }
                      else if (entry->type == SYM_LABEL || entry->type == SYM_FORWARD_LABEL)
                        {
                          instr->arg->type = ARG_ADDR_LABEL;
                          strncpy(instr->arg->u.label, str, MAX_LABEL_LEN - 1);
                          instr->arg->u.label[MAX_LABEL_LEN - 1] = '\0';
                        }
                      else if (entry->type == SYM_REG32)
                        {
                          instr->arg->type = ARG_ADDR_REG32;
                          instr->arg->u.reg = entry->u.value;
                        }
                      else
                        {
                          error(file_name, linenum, "Expected register or label.");
                          continue;
                        }
                      while (isspace(line[i]))
                        {
                          ++i;
                        }
                      if (line[i] != ']')
                        {
                          error(file_name, linenum, "Expected ].");
                          continue;
                        }
                      ++i;
                    }
                  else
                    {
                      error(file_name, linenum, "Expected instruction argument.");
                      return instr;
                    }

                  while (isspace(line[i]))
                    {
                      ++i;
                    }
                  if (line[i] == ',')
                    {
                      was_comma = 1;
                      ++i;
                    }
                  else
                    {
                      was_comma = 0;
                    }
                  while (isspace(line[i]))
                    {
                      ++i;
                    }
                  modifier = ARGMOD_NONE;
                } /* end while (not end of line)  */
              if (was_comma)
                {
                  error(file_name, linenum, "Unexpected comma.");
                }
            } /* end if (not end of line) */
          /* reverse back the order of arguments */
          if (instr->arg != NULL)
            {
              top = 0;
              la = instr->arg;
              while (la != NULL)
                {
                  stack[top++] = la;
                  la = la->next;
                  if (top >= MAX_ARGS)
                    {
                      fatal("argument stack overflow");
                    }
                }
              --top;
              for (i = top; i > 0; --i)
                {
                  stack[i]->next = stack[i - 1];
                }
              stack[0]->next = NULL;
              instr->arg = stack[top];
            }
          return instr;
        }
      else /* not fgets(...) != NULL */
        {
          fclose(file);
          file = NULL;
          return NULL;
        }
    } /* end for */
}

void free_instr(instr_t *instr)
{
  arg_t *la;

  if (instr == NULL)
    {
      return;
    }

  if (instr->arg != NULL)
    {
      la = instr->arg;
      while (la->next != NULL)
        {
          la = la->next;
        }
      la->next = pool_arg;
      pool_arg = instr->arg;
    }
  if (pool_instr == NULL)
    {
      pool_instr = instr;
    }
  else
    {
      free(instr);
    }
}

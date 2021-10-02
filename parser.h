#ifndef PARSER_H
#define PARSER_H

#include "limits.h"

#define OP_NONE -1

#define ARG_NONE 0
#define ARG_NUM 1
#define ARG_STR 2
#define ARG_LABEL 3
#define ARG_ADDR_REG32 4
#define ARG_ADDR_LABEL 5
#define ARG_REG32 6
#define ARG_REG8 7
#define ARG_DOT_IDENT 8 /* an identifier beginning with a dot: .text,
                           .data */

#define ARGMOD_NONE 0
#define ARGMOD_NEAR 1
#define ARGMOD_BYTE 2
#define ARGMOD_DWORD 3

typedef struct INSTR_ARG{
  int type;
  union{
    long value;
    char str[MAX_STR_LEN];
    char label[MAX_LABEL_LEN];
    int reg;
  } u;
  int modifier;
  struct INSTR_ARG *next;
} arg_t;

typedef struct{
  char label[MAX_LABEL_LEN];
  int opcode;
  arg_t *arg;
} instr_t;

extern int linenum; /* read-only */

void parser_init();
void parser_cleanup();
/* Opens a new file for parsing. */
void open_file(const char *path);
/* Parses the current line and returns the instruction read. The
   returned structure should be deallocated by the caller using
   free_instr(). Returns NULL on EOF. The file is automatically closed
   when EOF is reached. */
instr_t *get_instr();
void free_instr(instr_t *instr);

#endif /* PARSER_H */

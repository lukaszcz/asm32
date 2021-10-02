#ifndef SYMTAB_H
#define SYMTAB_H

#define SYM_REG32 1
/* type = SYM_REG32; value = register value; data - undefined */
#define SYM_REG8 2
/* type = SYM_REG8; value = register value; data - undefined */
#define SYM_LABEL 3
/* type = SYM_LABEL; value = symbol table index; data - undefined */
#define SYM_EXTERN 4
/* type = SYM_EXTERN; value = symbol table index; data - undefined */
#define SYM_FORWARD_LABEL 5
/* type = SYM_FORWARD_LABEL; value - undefined; data = pointer to
   fwd_label_t structure (see translator.c) */
#define SYM_OPCODE 6
/* type = SYM_OPCODE; value = opcode value; data - undefined */
#define SYM_ARGMOD 7
/* type = SYM_ARGMOD; value = argument modifier value; data -
   undefined */

typedef struct{
  int type;
  union{
    int value;
    void *data; /* additional data field */
  } u;
} entry_t;

void symtab_init();
void symtab_cleanup();
/* Inserts into the symbol table. Neither the key nor the entry are
   freed upon freeing the table. */
void symtab_insert(const char *key, entry_t *entry);
/* Searches the symbol table. Returns NULL if not found. */
entry_t *symtab_search(const char *key);

#endif /* SYMTAB_H */

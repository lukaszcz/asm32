#ifndef ELF_H
#define ELF_H

typedef int offset_t;
typedef enum { RELOC_REL = 0, RELOC_ABS = 1 } reloc_type_t;
typedef enum { SEC_TEXT = 0, SEC_DATA = 1, SEC_EXTERN = 2 } section_t;

typedef struct{
  offset_t offset;
  reloc_type_t type;
  int sym_idx; /* Note: symbol table indicies are 1-based, although
                  the table is 0-based */
} reloc_t;

typedef struct{
  char *name; /* symbol name; dynamically allocated */
  int value; /* symbol value (offset) */
  section_t section;
  int global; /* nonzero if global; zero if local */
  int strtab_idx; /* reserved for internal use by the module */
} sym_t;

void write_elf_file(const char *path,
                    const char *text, long text_len,
                    const char *data, long data_len,
                    sym_t *symbols, long symbols_num,
                    const reloc_t *relocs, long relocs_num);

#endif /* ELF_H */

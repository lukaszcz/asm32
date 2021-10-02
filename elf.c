#include <stdio.h>
#include <string.h>
#include <elf.h>

#include "limits.h"
#include "utils.h"
#include "elf.h"

#define SHDR_OFFSET sizeof(Elf32_Ehdr)
#define TEXT_INDEX 1
#define DATA_INDEX 2
#define STRTAB_INDEX 3 /* index of .strtab section in the section
                          header */
#define SYMTAB_INDEX 4
#define STRTAB_EXTRA_SPACE 39 /* for section names and the initial
                                 zero */

#define SECTIONS 6

#define TEXT_STRTAB_INDEX 1
#define DATA_STRTAB_INDEX 7
#define STRTAB_STRTAB_INDEX 13
#define SYMTAB_STRTAB_INDEX 21
#define REL_TEXT_STRTAB_INDEX 29

/* locals go first */
static void partition_symbols(sym_t *symbols, long n, long *sym_indices)
{
  long i, j;

  /* symbol indices are 1-based */
  --symbols;
  i = 1; j = n;
  while (i < j)
    {
      while (i < j && symbols[i].global == 0)
        {
          sym_indices[i] = i;
          ++i;
        }
      while (j > i && symbols[j].global)
        {
          sym_indices[j] = j;
          --j;
        }
      if (i < j)
        {
          sym_indices[i] = j;
          sym_indices[j] = i;
          ++i;
          --j;
        }
      if (i == j)
        {
          sym_indices[i] = i;
        }
    }
}

void write_elf_file(const char *path,
                    const char *text, long text_len,
                    const char *data, long data_len,
                    sym_t *symbols, long symbols_num,
                    const reloc_t *relocs, long relocs_num)
{
  Elf32_Ehdr hdr;
  Elf32_Shdr shdr;
  Elf32_Sym sym;
  Elf32_Rel rel;
  FILE *file;
  offset_t text_offset, data_offset, strtab_offset, symtab_offset, reloc_offset;
  int symtab_len, i, j, strtab_len, reloc_len, idx, local_syms;
  long sym_indices[MAX_SYMBOLS + 1];

  if ((file = fopen(path, "w")) == NULL)
    {
      syserr("Cannot open output file.");
    }

  /* partition symbol entries - locals go first */
  partition_symbols(symbols, symbols_num, sym_indices);

  hdr.e_ident[EI_MAG0] = ELFMAG0;
  hdr.e_ident[EI_MAG1] = ELFMAG1;
  hdr.e_ident[EI_MAG2] = ELFMAG2;
  hdr.e_ident[EI_MAG3] = ELFMAG3;
  hdr.e_ident[EI_CLASS] = ELFCLASS32;
  hdr.e_ident[EI_DATA] = ELFDATA2LSB;
  hdr.e_ident[EI_VERSION] = EV_CURRENT;
  hdr.e_ident[EI_OSABI] = ELFOSABI_LINUX;
  hdr.e_ident[EI_ABIVERSION] = 0;
  hdr.e_ident[EI_PAD] = 0;
  for (i = EI_PAD; i < EI_NIDENT; ++i)
    {
      hdr.e_ident[i] = 0;
    }
  hdr.e_type = ET_REL;
  hdr.e_machine = EM_386;
  hdr.e_version = EV_CURRENT;
  hdr.e_entry = 0;
  hdr.e_phoff = 0;
  hdr.e_shoff = SHDR_OFFSET;
  hdr.e_flags = 0;
  hdr.e_ehsize = sizeof(hdr);
  hdr.e_phentsize = 0;
  hdr.e_phnum = 0;
  hdr.e_shentsize = sizeof(Elf32_Shdr);
  hdr.e_shnum = 6;
  hdr.e_shstrndx = STRTAB_INDEX;
  if (fwrite(&hdr, sizeof(hdr), 1, file) != 1)
    {
      syserr("fwrite error");
    }

  /* zero section */
  shdr.sh_name = 0;
  shdr.sh_type = SHT_NULL;
  shdr.sh_flags = 0;
  shdr.sh_addr = 0;
  shdr.sh_offset = 0;
  shdr.sh_size = 0;
  shdr.sh_link = SHN_UNDEF;
  shdr.sh_info = 0;
  shdr.sh_addralign = 0;
  shdr.sh_entsize = 0;
  if (fwrite(&shdr, sizeof(shdr), 1, file) != 1)
    {
      syserr("fwrite error");
    }

  text_offset = sizeof(hdr) + SECTIONS * sizeof(shdr);
  /* .text section */
  shdr.sh_name = TEXT_STRTAB_INDEX;
  if (text_len != 0)
    {
      shdr.sh_type = SHT_PROGBITS;
    }
  else
    {
      shdr.sh_type = SHT_NOBITS;
    }
  shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  shdr.sh_addr = 0;
  shdr.sh_offset = text_offset;
  shdr.sh_size = text_len;
  shdr.sh_link = SHN_UNDEF;
  shdr.sh_info = 0;
  shdr.sh_addralign = 4;
  shdr.sh_entsize = 0;
  if (fwrite(&shdr, sizeof(shdr), 1, file) != 1)
    {
      syserr("fwrite error");
    }

  data_offset = text_offset + text_len;
  /* .data section */
  shdr.sh_name = DATA_STRTAB_INDEX;
  if (data_len != 0)
    {
      shdr.sh_type = SHT_PROGBITS;
    }
  else
    {
      shdr.sh_type = SHT_NOBITS;
    }
  shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
  shdr.sh_addr = 0;
  shdr.sh_offset = data_offset;
  shdr.sh_size = data_len;
  shdr.sh_link = SHN_UNDEF;
  shdr.sh_info = 0;
  shdr.sh_addralign = 4;
  shdr.sh_entsize = 0;
  if (fwrite(&shdr, sizeof(shdr), 1, file) != 1)
    {
      syserr("fwrite error");
    }

  /* count the overall size of .strtab */
  strtab_len = STRTAB_EXTRA_SPACE;
  for (i = 0; i < symbols_num; ++i)
    {
      strtab_len += strlen(symbols[i].name) + 1;
    }

  strtab_offset = data_offset + data_len;
  /* .strtab section */
  shdr.sh_name = STRTAB_STRTAB_INDEX;
  shdr.sh_type = SHT_STRTAB;
  shdr.sh_flags = 0;
  shdr.sh_addr = 0;
  shdr.sh_offset = strtab_offset;
  shdr.sh_size = strtab_len;
  shdr.sh_link = SHN_UNDEF;
  shdr.sh_info = 0;
  shdr.sh_addralign = 4;
  shdr.sh_entsize = 0;
  if (fwrite(&shdr, sizeof(shdr), 1, file) != 1)
    {
      syserr("fwrite error");
    }

  /* count the number of local symbols */
  local_syms = 0;
  for (i = 0; i < symbols_num; ++i)
    {
      if (!symbols[i].global)
        {
          ++local_syms;
        }
    }

  symtab_offset = strtab_offset + strtab_len;
  symtab_len = (symbols_num + 1) * sizeof(Elf32_Sym);
  /* .symtab section */
  shdr.sh_name = SYMTAB_STRTAB_INDEX;
  shdr.sh_type = SHT_SYMTAB;
  shdr.sh_flags = 0;
  shdr.sh_addr = 0;
  shdr.sh_offset = symtab_offset;
  shdr.sh_size = symtab_len;
  shdr.sh_link = STRTAB_INDEX;
  shdr.sh_info = local_syms + 1;
  shdr.sh_addralign = 4;
  shdr.sh_entsize = sizeof(Elf32_Sym);
  if (fwrite(&shdr, sizeof(shdr), 1, file) != 1)
    {
      syserr("fwrite error");
    }

  reloc_offset = symtab_offset + symtab_len;
  reloc_len = relocs_num * sizeof(Elf32_Rel);
  /* .rel.text section */
  shdr.sh_name = REL_TEXT_STRTAB_INDEX;
  if (reloc_len != 0)
    {
      shdr.sh_type = SHT_REL;
    }
  else
    {
      shdr.sh_type = SHT_NOBITS;
    }
  shdr.sh_flags = 0;
  shdr.sh_addr = 0;
  shdr.sh_offset = reloc_offset;
  shdr.sh_size = reloc_len;
  shdr.sh_link = SYMTAB_INDEX;
  shdr.sh_info = TEXT_INDEX;
  shdr.sh_addralign = 4;
  shdr.sh_entsize = sizeof(Elf32_Rel);
  if (fwrite(&shdr, sizeof(shdr), 1, file) != 1)
    {
      syserr("fwrite error");
    }

  /* write sections' contents */

  /* .text section */
  if (text_len != 0)
    {
      if (fwrite(text, text_len, 1, file) != 1)
        {
          syserr("fwrite error");
        }
    }

  /* .data section */
  if (data_len != 0)
    {
      if (fwrite(data, data_len, 1, file) != 1)
        {
          syserr("fwrite error");
        }
    }

  /* .strtab section */
  fputc('\0', file);
  fputs(".text", file); // 1
  fputc('\0', file);
  fputs(".data", file); // 7
  fputc('\0', file);
  fputs(".strtab", file); // 13
  fputc('\0', file);
  fputs(".symtab", file); // 21
  fputc('\0', file);
  fputs(".rel.text", file); // 29
  fputc('\0', file);
  idx = STRTAB_EXTRA_SPACE;
  for (i = 0; i < symbols_num; ++i)
    {
      fputs(symbols[i].name, file);
      fputc('\0', file);
      symbols[i].strtab_idx = idx;
      idx += strlen(symbols[i].name) + 1;
    }

  /* .symtab section  */
  sym.st_name = 0;
  sym.st_value = 0;
  sym.st_size = 0;
  sym.st_other = 0;
  sym.st_shndx = SHN_UNDEF;
  sym.st_info = 0;
  if (fwrite(&sym, sizeof(sym), 1, file) != 1)
    {
      syserr("fwrite error");
    }

  for (i = 0; i < symbols_num; ++i)
    {
      j = sym_indices[i + 1] - 1;
      sym.st_name = symbols[j].strtab_idx;
      sym.st_value = symbols[j].value;
      sym.st_size = 0;
      if (symbols[j].global)
        {
          sym.st_info = ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE);
        }
      else
        {
          sym.st_info = ELF32_ST_INFO(STB_LOCAL, STT_NOTYPE);
        }
      sym.st_other = 0;
      switch (symbols[j].section){
      case SEC_TEXT:
        sym.st_shndx = TEXT_INDEX;
        break;
      case SEC_DATA:
        sym.st_shndx = DATA_INDEX;
        break;
      case SEC_EXTERN:
        sym.st_shndx = SHN_UNDEF;
        break;
      default:
        fatal("programming error");
        break;
      };
      if (fwrite(&sym, sizeof(sym), 1, file) != 1)
        {
          syserr("fwrite error");
        }
    }

  /* .rel.text section */
  for (i = 0; i < relocs_num; ++i)
    {
      rel.r_offset = relocs[i].offset;
      if (relocs[i].type == RELOC_REL)
        {
          rel.r_info = ELF32_R_INFO(sym_indices[relocs[i].sym_idx], R_386_PC32);
        }
      else
        {
          rel.r_info = ELF32_R_INFO(sym_indices[relocs[i].sym_idx], R_386_32);
        }
      if (fwrite(&rel, sizeof(rel), 1, file) != 1)
        {
          syserr("fwrite error");
        }
    }
  fclose(file);
}

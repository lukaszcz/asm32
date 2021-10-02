#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "limits.h"
#include "utils.h"
#include "symtab.h"
#include "elf.h"
#include "parser.h"
#include "translator.h"

#define MOD_REG 3

#define REF_REL_1 0 /* relative reference occupying one byte */
#define REF_REL_4 1 /* relative reference occupying four bytes */
#define REF_ABS 2 /* absolute reference */

#define REG_EAX 0
#define REG_EBX 3
#define REG_ECX 1
#define REG_EDX 2
#define REG_ESI 6
#define REG_EDI 7
#define REG_EBP 5
#define REG_ESP 4

#define REG_AL 0
#define REG_BL 3
#define REG_CL 1
#define REG_DL 2
#define REG_AH 4
#define REG_BH 7
#define REG_CH 5
#define REG_DH 6

#define OP_MOV 0
#define OP_ADD 1
#define OP_SUB 2
#define OP_MUL 3
#define OP_DIV 4
#define OP_CMP 5
#define OP_JE 6
#define OP_JNE 7
#define OP_JG 8
#define OP_JL 9
#define OP_JGE 10
#define OP_JLE 11
#define OP_JMP 12
#define OP_INT 13
#define OP_CALL 14
#define OP_RET 15
#define OP_PUSH 16
#define OP_POP 17
#define OP_DB 18
#define OP_DD 19
#define OP_SECTION 20
#define OP_EXTERN 21
#define OP_GLOBAL 22
#define OPCODES_NUMBER 23


typedef struct Struct_ref{
  offset_t offset; /* offset of the place which refers to the label */
  int type; /* reference type: REF_REL_1, REF_REL_4 or REF_ABS */
  int linenum; /* line number of the reference in the input file */
  struct Struct_ref *next;
} ref_t;

typedef struct Struct_fwd_label{
  ref_t *ref; /* reference chain */
  char *label; /* label name; dynamically allocated */
  int global; /* nonzero if the label is global */
  struct Struct_fwd_label *next;
  struct Struct_fwd_label *prev;
} fwd_label_t;

#define MODRM_ABSENT 0x10
#define MODRM_REG 0x20
#define OPARG_PREFIX_0F 0x40
#define OPARG_INVALID 0x80

#define IS_VALID(des) (((des).modrm & OPARG_INVALID) == 0)
#define IS_PREFIX_0F(des) (((des).modrm & OPARG_PREFIX_0F) != 0)
#define MODRM_MIDDLE(des) ((des).modrm & 0x0F)

#define MODRM(mod, middle, rm) (((mod) << 6) | ((middle) << 3) | (rm))
#define SIB(scale, index, base) (((scale) << 6) | ((index) << 3) | (base))

#define OPARG_REG8 0
#define OPARG_REG32 1
#define OPARG_MEM8 2
#define OPARG_MEM32 3
#define OPARG_IMM8 4
#define OPARG_IMM32 5
#define OPARG1_NUMBER 6

#define OPARG_REL8 0
#define OPARG_REL32 1
#define OPARG1_REL_NUMBER 2

#define OPARG_REG8_RM8 0
#define OPARG_RM8_REG8 1
#define OPARG_REG8_IMM8 2
#define OPARG_MEM8_IMM8 3
#define OPARG_REG32_RM32 4
#define OPARG_RM32_REG32 5
#define OPARG_REG32_IMM32 6
#define OPARG_MEM32_IMM32 7
#define OPARG_RM32_IMM8 8
#define OPARG_AL_IMM8 9
#define OPARG_EAX_IMM32 10
#define OPARG2_NUMBER 11

typedef struct{
  unsigned char code;
  unsigned char modrm; /* This is set to OPARG_INVALID if a given
                 combination of operands is not valid for a given
                 instruction. */
} instr_descr_t;

typedef struct{
  instr_descr_t arg0;
  instr_descr_t arg1[OPARG1_NUMBER];
  instr_descr_t arg2[OPARG2_NUMBER];
  instr_descr_t arg1_rel[OPARG1_REL_NUMBER];
  int arg0_valid; /* Nonzero if the instruction may have 0/1/2
                     operands. */
  int arg1_valid;
  int arg2_valid;
  int arg1_rel_valid;
} opinstr_t;


#define WRITE_BYTE(byte) \
  sec[csec][sec_offset[csec]++] = (byte);

#define WRITE_DWORD(dword) \
  sec[csec][sec_offset[csec]++] = (dword) & 0xFF; \
  sec[csec][sec_offset[csec]++] = ((dword) >> 8) & 0xFF; \
  sec[csec][sec_offset[csec]++] = ((dword) >> 16) & 0xFF; \
  sec[csec][sec_offset[csec]++] = ((dword) >> 24) & 0xFF;

#define SIGNED_FITS_IN_BYTE(value) ((((unsigned) (value)) & 0xFFFFFF80) == 0 || \
                                    (((unsigned) (value)) & 0xFFFFFF80) == 0xFFFFFF80)

#define FITS_IN_BYTE(value) ((((unsigned) (value)) & 0xFFFFFF00) == 0 || \
                             (((unsigned) (value)) & 0xFFFFFF80) == 0xFFFFFF80)


/*****************************************************************************/
/* Global (module-local) data. */

static char *sec[MAX_SECTIONS]; /* section data */
static int sec_offset[MAX_SECTIONS]; /* current offset within section */
static int sec_max_size[MAX_SECTIONS]; /* size of memory current
                                          allocated for the
                                          corresponding section */
static int csec; /* current section number (index into the above tables) */
static const char *cfile;

static reloc_t relocs[MAX_RELOCATIONS];
static int r_top;
static opinstr_t opinstr[OPCODES_NUMBER];
static fwd_label_t *forward_labels;
static entry_t symtab_entries[SYMTAB_SIZE + 1];
  /* +1 to avoid checking whether the table is full (if it is there
     will be a fatal error in symtab_insert()) */
static int se_top;
static sym_t symbols[MAX_SYMBOLS];
static int s_top;

/*****************************************************************************/
/* Helper functions. */

static void add_label(const char *label);
static entry_t *add_forward_label(const char *label, int ref_type);
static void write_abs_label(const char *label);
static void write_instr_arg1_reg(arg_t *arg1, instr_descr_t des);
static void write_instr_modrm_mem(int middle, arg_t *arg, instr_descr_t des);
static void write_instr_arg1_rel(arg_t *arg1, instr_descr_t *ides);
static void generic_instr_process(instr_t *instr);

/*****************************************************************************/

static void add_label(const char *label)
{
  entry_t *pe;
  fwd_label_t *fwd;
  ref_t *r;
  ref_t *rn;
  int diff, value;

  pe = symtab_search(label);
  ++s_top;
  if (s_top >= MAX_SYMBOLS)
    {
      fatal("Too many symbols.");
    }
  symbols[s_top].name = xstrdup(label);
  symbols[s_top].value = sec_offset[csec];
  symbols[s_top].section = csec;
  symbols[s_top].global = 0;
  if (pe != NULL)
    {
      if (pe->type == SYM_FORWARD_LABEL)
        {
          fwd = (fwd_label_t*) pe->u.data;
          if (fwd->global)
            {
              symbols[s_top].global = 1;
            }
          r = fwd->ref;
          /* r may be NULL if it was defined with a global
             pseudoinstruction but as yet never used */
          while (r != NULL)
            {
              switch(r->type){
              case REF_REL_1:
                diff = sec_offset[csec] - r->offset - 1;
                if (SIGNED_FITS_IN_BYTE(diff))
                  {
                    sec[csec][r->offset] = diff;
                  }
                else
                  {
                    error(cfile, r->linenum, "Label out of range. Use the `near' modifier.");
                  }
                break;
              case REF_REL_4:
                value = sec_offset[csec] - r->offset - 4;
                sec[csec][r->offset] = value & 0xFF;
                sec[csec][r->offset + 1] = (value >> 8) & 0xFF;
                sec[csec][r->offset + 2] = (value >> 16) & 0xFF;
                sec[csec][r->offset + 3] = (value >> 24) & 0xFF;
                break;
              case REF_ABS:
                ++r_top;
                if (r_top >= MAX_RELOCATIONS)
                  {
                    fatal("Too many relocations.");
                  }
                relocs[r_top].offset = r->offset;
                relocs[r_top].type = RELOC_ABS;
                relocs[r_top].sym_idx = s_top;
                break;
              };
              rn = r->next;
              free(r);
              r = rn;
            }
          if (fwd->prev != NULL)
            {
              fwd->prev->next = fwd->next;
            }
          else
            {
              forward_labels = fwd->next;
            }
          if (fwd->next != NULL)
            {
              fwd->next->prev = fwd->prev;
            }
          free(symbols[s_top].name);
          symbols[s_top].name = fwd->label;
          free(fwd);
          pe->u.value = s_top;
          pe->type = SYM_LABEL;
        }
      else
        {
          error(cfile, linenum, "Duplicate identifier.");
        }
    }
  else /* not (pe != NULL) */
    {
      ++se_top;
      pe = &symtab_entries[se_top];
      pe->u.value = s_top;
      pe->type = SYM_LABEL;
      symtab_insert(symbols[s_top].name, pe);
    }
}

static entry_t *add_forward_label(const char *label, int ref_type)
{
  ref_t *r;
  fwd_label_t *fwd;
  entry_t *pe;

  r = (ref_t*) xmalloc(sizeof(ref_t));
  r->next = 0;
  r->type = ref_type;
  r->offset = sec_offset[csec];
  r->linenum = linenum;
  fwd = (fwd_label_t*) xmalloc(sizeof(fwd_label_t));
  fwd->ref = r;
  fwd->label = xstrdup(label);
  fwd->next = forward_labels;
  if (forward_labels != NULL)
    {
      forward_labels->prev = fwd;
    }
  fwd->prev = NULL;
  forward_labels = fwd;

  ++se_top;
  pe = &symtab_entries[se_top];
  pe->type = SYM_FORWARD_LABEL;
  pe->u.data = fwd;
  symtab_insert(fwd->label, pe);

  return pe;
}

static void write_abs_label(const char *label)
{
  entry_t *pe;
  fwd_label_t *fwd;
  ref_t *r;
  int was_fwd_added = 0;
  pe = symtab_search(label);
  if (pe == NULL)
    {
      pe = add_forward_label(label, REF_ABS);
      was_fwd_added = 1;
    }

  switch(pe->type){
  case SYM_FORWARD_LABEL:
    if (!was_fwd_added)
      {
        fwd = (fwd_label_t*) pe->u.data;
        r = (ref_t*) xmalloc(sizeof(ref_t));
        r->next = fwd->ref;
        r->type = REF_ABS;
        r->offset = sec_offset[csec];
        r->linenum = linenum;
        fwd->ref = r;
      }
    WRITE_DWORD(0);
    break;

  case SYM_LABEL:
    ++r_top;
    if (r_top >= MAX_RELOCATIONS)
      {
        fatal("Too many relocations.");
      }
    relocs[r_top].offset = sec_offset[csec];
    relocs[r_top].type = RELOC_ABS;
    relocs[r_top].sym_idx = pe->u.value;
    WRITE_DWORD(symbols[pe->u.value].value);
    break;

  case SYM_EXTERN:
    ++r_top;
    if (r_top >= MAX_RELOCATIONS)
      {
        fatal("Too many relocations.");
      }
    relocs[r_top].offset = sec_offset[csec];
    relocs[r_top].type = RELOC_ABS;
    relocs[r_top].sym_idx = pe->u.value;
    WRITE_DWORD(0);
    break;

  default:
    error(cfile, linenum, "Expected a label.");
    break;
  };
}

static void write_instr_arg1_reg(arg_t *arg1, instr_descr_t des)
{
  if (!IS_VALID(des))
    {
      error(cfile, linenum, "Wrong operand type.");
      return;
    }
  if (IS_PREFIX_0F(des))
    {
      WRITE_BYTE(0x0F);
    }
  if ((des.modrm & MODRM_ABSENT) != 0)
    {
      WRITE_BYTE(des.code + arg1->u.reg);
    }
  else
    {
      WRITE_BYTE(des.code);
      WRITE_BYTE(MODRM(MOD_REG, MODRM_MIDDLE(des), arg1->u.reg));
    }
}

static void write_instr_modrm_mem(int middle, arg_t *arg, instr_descr_t des)
{
  assert ((des.modrm & MODRM_ABSENT) == 0);
  if (IS_PREFIX_0F(des))
    {
      WRITE_BYTE(0x0F);
    }
  WRITE_BYTE(des.code);
  if (arg->type == ARG_ADDR_LABEL)
    {
      WRITE_BYTE(MODRM(0, middle, 5));
      write_abs_label(arg->u.label);
    }
  else /* ARG_ADDR_REG32 */
    {
      if (arg->u.reg == 4)
        {
          WRITE_BYTE(MODRM(0, middle, 4));
          WRITE_BYTE(SIB(0, 4, 4));
        }
      else if (arg->u.reg == 5)
        {
          WRITE_BYTE(MODRM(0, middle, 4));
          WRITE_BYTE(SIB(1, 4, 5));
          WRITE_BYTE(0);
        }
      else
        {
          WRITE_BYTE(MODRM(0, middle, arg->u.reg));
        }
    }
}

static void write_instr_arg1_rel(arg_t *arg1, instr_descr_t *ides)
{
  entry_t *pe;
  fwd_label_t *fwd;
  ref_t *r;
  int size, diff;

  assert(arg1->type == ARG_LABEL);

  if (arg1->modifier != ARGMOD_NONE && arg1->modifier != ARGMOD_NEAR)
    {
      error(cfile, linenum, "Wrong operand modifier.");
    }

  pe = symtab_search(arg1->u.label);
  if (pe == NULL)
    {
      if (IS_VALID(ides[OPARG_REL8]) && arg1->modifier == ARGMOD_NONE)
        {
          size = 1;
          assert (!IS_PREFIX_0F(ides[OPARG_REL8]));
          WRITE_BYTE(ides[OPARG_REL8].code);
        }
      else
        {
          size = 4;
          if (IS_PREFIX_0F(ides[OPARG_REL32]))
            {
              WRITE_BYTE(0x0F);
            }
          WRITE_BYTE(ides[OPARG_REL32].code);
        }

      add_forward_label(arg1->u.label,
                        (arg1->modifier == ARGMOD_NEAR || !IS_VALID(ides[OPARG_REL8])) ?
                        REF_REL_4 : REF_REL_1);

      if (size == 1)
        {
          WRITE_BYTE(0);
        }
      else
        {
          WRITE_DWORD(0);
        }
    }
  else
    {
      switch(pe->type){
      case SYM_FORWARD_LABEL:
        if (IS_VALID(ides[OPARG_REL8]) && arg1->modifier == ARGMOD_NONE)
          {
            size = 1;
            assert (!IS_PREFIX_0F(ides[OPARG_REL8]));
            WRITE_BYTE(ides[OPARG_REL8].code);
          }
        else
          {
            size = 4;
            if (IS_PREFIX_0F(ides[OPARG_REL32]))
              {
                WRITE_BYTE(0x0F);
              }
            WRITE_BYTE(ides[OPARG_REL32].code);
          }

        fwd = (fwd_label_t*) pe->u.data;
        r = (ref_t*) xmalloc(sizeof(ref_t));
        r->next = fwd->ref;
        if (size == 1)
          {
            r->type = REF_REL_1;
          }
        else
          {
            r->type = REF_REL_4;
          }
        r->offset = sec_offset[csec];
        r->linenum = linenum;
        fwd->ref = r;

        if (size == 1)
          {
            WRITE_BYTE(0);
          }
        else
          {
            WRITE_DWORD(0);
          }
        break;

      case SYM_LABEL:
        diff = symbols[pe->u.value].value - sec_offset[csec] - 2;
        if (IS_VALID(ides[OPARG_REL8]) && SIGNED_FITS_IN_BYTE(diff))
          {
            assert (!IS_PREFIX_0F(ides[OPARG_REL8]));
            WRITE_BYTE(ides[OPARG_REL8].code);
            WRITE_BYTE(diff);
          }
        else
          {
            assert (IS_VALID(ides[OPARG_REL32]));
            diff -= 3;
            if (IS_PREFIX_0F(ides[OPARG_REL32]))
              {
                WRITE_BYTE(0x0F);
                --diff;
              }
            WRITE_BYTE(ides[OPARG_REL32].code);
            WRITE_DWORD(diff);
          }
        break;

      case SYM_EXTERN:
        if (IS_VALID(ides[OPARG_REL32]))
          {
            if (IS_PREFIX_0F(ides[OPARG_REL32]))
              {
                WRITE_BYTE(0x0F);
              }
            WRITE_BYTE(ides[OPARG_REL32].code);
            ++r_top;
            if (r_top >= MAX_RELOCATIONS)
              {
                fatal("Too many relocations.");
              }
            relocs[r_top].offset = sec_offset[csec];
            relocs[r_top].type = RELOC_REL;
            relocs[r_top].sym_idx = pe->u.value;
            WRITE_DWORD(0);
          }
        else
          {
            error(cfile, linenum, "Invalid operand.");
          }
        break;

      default:
        error(cfile, linenum, "Invalid operand.");
        break;
      };
    } /* end if */
}

static void generic_instr_process(instr_t *instr)
{
  arg_t *arg1;
  arg_t *arg2;
  int arg1_uses_modifier;
  instr_descr_t *ides;

  arg1 = instr->arg;
  if (arg1 != NULL)
    {
      arg2 = arg1->next;
    }
  else
    {
      arg2 = NULL;
    }
  if (arg2 != NULL && arg2->next != NULL)
    {
      error(cfile, linenum, "Wrong number of operands.");
      return;
    }
  if (arg1 == NULL)
    {
      if (opinstr[instr->opcode].arg0_valid)
        {
          sec[csec][sec_offset[csec]++] = opinstr[instr->opcode].arg0.code;
        }
      else
        {
          error(cfile, linenum, "Wrong number of operands.");
          return;
        }
    }
  else if (arg2 == NULL)
    {
      if (opinstr[instr->opcode].arg1_valid)
        {
          arg1_uses_modifier = 0;
          ides = opinstr[instr->opcode].arg1;
          switch(arg1->type){
          case ARG_REG8:
            write_instr_arg1_reg(arg1, ides[OPARG_REG8]);
            break;

          case ARG_REG32:
            write_instr_arg1_reg(arg1, ides[OPARG_REG32]);
            break;

          case ARG_NUM:
            if (FITS_IN_BYTE(arg1->u.value) && IS_VALID(ides[OPARG_IMM8]))
              {
                WRITE_BYTE(ides[OPARG_IMM8].code);
                WRITE_BYTE(arg1->u.value);
                assert ((ides[OPARG_IMM8].modrm & MODRM_ABSENT) != 0);
              }
            else if (IS_VALID(ides[OPARG_IMM32]))
              {
                WRITE_BYTE(ides[OPARG_IMM32].code);
                WRITE_DWORD(arg1->u.value);
                assert ((ides[OPARG_IMM8].modrm & MODRM_ABSENT) != 0);
              }
            else
              {
                error(cfile, linenum, "Wrong operand type.");
              }
            break;

          case ARG_LABEL:
            if (IS_VALID(ides[OPARG_IMM32]))
              {
                WRITE_BYTE(ides[OPARG_IMM32].code);
                write_abs_label(arg1->u.label);
              }
            break;

          case ARG_ADDR_LABEL:
          case ARG_ADDR_REG32:
            arg1_uses_modifier = 1;
            if (arg1->modifier == ARGMOD_BYTE ||
                (arg1->modifier == ARGMOD_NONE && !IS_VALID(ides[OPARG_MEM32])))
              {
                if (IS_VALID(ides[OPARG_MEM8]))
                  {
                    write_instr_modrm_mem(MODRM_MIDDLE(ides[OPARG_MEM8]), arg1, ides[OPARG_MEM8]);
                  }
                else
                  {
                    error(cfile, linenum, "Invalid operand.");
                  }
              }
            else if (arg1->modifier == ARGMOD_DWORD ||
                     (arg1->modifier == ARGMOD_NONE && !IS_VALID(ides[OPARG_MEM8])))
              {
                if (IS_VALID(ides[OPARG_MEM32]))
                  {
                    write_instr_modrm_mem(MODRM_MIDDLE(ides[OPARG_MEM32]), arg1, ides[OPARG_MEM32]);
                  }
                else
                  {
                    error(cfile, linenum, "Invalid operand.");
                  }
              }
            else
              {
                error(cfile, linenum,
                      "Operand size unspecified. Use `byte' or `dword' modifier.");
              }
            break;

          default:
            error(cfile, linenum, "Invalid operand.");
            break;
          }
        }
      else if (opinstr[instr->opcode].arg1_rel_valid)
        {
          if (arg1->type == ARG_LABEL)
            {
              write_instr_arg1_rel(arg1, opinstr[instr->opcode].arg1);
            }
          else
            {
              error(cfile, linenum, "Invalid operand.");
            }
          arg1_uses_modifier = 1;
        }
      else
        {
          error(cfile, linenum, "Wrong number of operands.");
          return;
        }
      if (!arg1_uses_modifier && arg1->modifier != ARGMOD_NONE)
        {
          error(cfile, linenum, "Useless modifier.");
        }
    }
  else /* two operands; arg2 != NULL */
    {
      if (!opinstr[instr->opcode].arg2_valid)
        {
          error(cfile, linenum, "Wrong arguments.");
          return;
        }
      ides = opinstr[instr->opcode].arg2;
      switch(arg1->type){
      case ARG_REG8:
        switch(arg2->type){
        case ARG_REG8:
          if (!IS_VALID(ides[OPARG_REG8_RM8]))
            {
              error(cfile, linenum, "Invalid operand.");
              break;
            }
          assert((ides[OPARG_REG8_RM8].modrm & MODRM_ABSENT) == 0);
          assert((ides[OPARG_REG8_RM8].modrm & MODRM_REG) != 0);
          WRITE_BYTE(ides[OPARG_REG8_RM8].code);
          WRITE_BYTE(MODRM(MOD_REG, arg1->u.reg, arg2->u.reg));
          break;

        case ARG_NUM:
          if (FITS_IN_BYTE(arg2->u.value))
            {
              if (arg1->u.reg == REG_AL && IS_VALID(ides[OPARG_AL_IMM8]))
                {
                  WRITE_BYTE(ides[OPARG_AL_IMM8].code);
                }
              else
                {
                  if (!IS_VALID(ides[OPARG_REG8_IMM8]))
                    {
                      error(cfile, linenum, "Invalid operand.");
                      break;
                    }
                  if ((ides[OPARG_REG8_IMM8].modrm & MODRM_ABSENT) != 0)
                    {
                      WRITE_BYTE(ides[OPARG_REG8_IMM8].code + arg1->u.reg);
                    }
                  else
                    {
                      WRITE_BYTE(ides[OPARG_REG8_IMM8].code);
                      WRITE_BYTE(MODRM(MOD_REG, MODRM_MIDDLE(ides[OPARG_REG8_IMM8]), arg1->u.reg));
                    }
                }
              WRITE_BYTE(arg2->u.value);
            }
          else
            {
              error(cfile, linenum,
                    "Constant too large - doesn't fit in one byte.");
            }
          break;

        case ARG_ADDR_LABEL:
        case ARG_ADDR_REG32:
          if (!IS_VALID(ides[OPARG_REG8_RM8]))
            {
              error(cfile, linenum, "Invalid operand.");
              break;
            }
          assert((ides[OPARG_REG8_RM8].modrm & MODRM_ABSENT) == 0);
          assert((ides[OPARG_REG8_RM8].modrm & MODRM_REG) != 0);
          write_instr_modrm_mem(arg1->u.reg, arg2, ides[OPARG_REG8_RM8]);
          break;

        default:
          error(cfile, linenum, "Invalid operand.");
          break;
        };
        break;

      case ARG_REG32:
        switch(arg2->type){
        case ARG_REG32:
          if (!IS_VALID(ides[OPARG_REG32_RM32]))
            {
              error(cfile, linenum, "Invalid operand.");
              break;
            }
          assert((ides[OPARG_REG32_RM32].modrm & MODRM_ABSENT) == 0);
          assert((ides[OPARG_REG32_RM32].modrm & MODRM_REG) != 0);
          WRITE_BYTE(ides[OPARG_REG32_RM32].code);
          WRITE_BYTE(MODRM(MOD_REG, arg1->u.reg, arg2->u.reg));
          break;

        case ARG_NUM:
          if (FITS_IN_BYTE(arg2->u.value) && IS_VALID(ides[OPARG_RM32_IMM8]))
            {
              assert ((ides[OPARG_RM32_IMM8].modrm & MODRM_ABSENT) == 0);
              WRITE_BYTE(ides[OPARG_RM32_IMM8].code);
              WRITE_BYTE(MODRM(MOD_REG, MODRM_MIDDLE(ides[OPARG_RM32_IMM8]), arg1->u.reg));
              WRITE_BYTE(arg2->u.value);
            }
          else if (arg1->u.reg == REG_EAX && IS_VALID(ides[OPARG_EAX_IMM32]))
            {
              WRITE_BYTE(ides[OPARG_EAX_IMM32].code);
              WRITE_DWORD(arg2->u.value);
            }
          else
            {
              if (!IS_VALID(ides[OPARG_REG32_IMM32]))
                {
                  error(cfile, linenum, "Invalid operand.");
                  break;
                }
              if ((ides[OPARG_REG32_IMM32].modrm & MODRM_ABSENT) != 0)
                {
                  WRITE_BYTE(ides[OPARG_REG32_IMM32].code + arg1->u.reg);
                }
              else
                {
                  WRITE_BYTE(ides[OPARG_REG32_IMM32].code);
                  WRITE_BYTE(MODRM(MOD_REG, MODRM_MIDDLE(ides[OPARG_RM32_IMM8]), arg1->u.reg));
                }
              WRITE_DWORD(arg2->u.value);
            }
          break;

        case ARG_LABEL:
          if (!IS_VALID(ides[OPARG_REG32_IMM32]))
            {
              error(cfile, linenum, "Invalid operand.");
              break;
            }
          if ((ides[OPARG_REG32_IMM32].modrm & MODRM_ABSENT) != 0)
            {
              WRITE_BYTE(ides[OPARG_REG32_IMM32].code + arg1->u.reg);
            }
          else
            {
              WRITE_BYTE(ides[OPARG_REG32_IMM32].code);
              WRITE_BYTE(MODRM(MOD_REG, MODRM_MIDDLE(ides[OPARG_RM32_IMM8]), arg1->u.reg));
            }
          write_abs_label(arg2->u.label);
          break;

        case ARG_ADDR_LABEL:
        case ARG_ADDR_REG32:
          if (!IS_VALID(ides[OPARG_REG32_RM32]))
            {
              error(cfile, linenum, "Invalid operand.");
              break;
            }
          assert((ides[OPARG_REG32_RM32].modrm & MODRM_ABSENT) == 0);
          assert((ides[OPARG_REG32_RM32].modrm & MODRM_REG) != 0);
          write_instr_modrm_mem(arg1->u.reg, arg2, ides[OPARG_REG32_RM32]);
          break;

        default:
          error(cfile, linenum, "Invalid operand.");
          break;
        };
        break;

      case ARG_ADDR_LABEL:
      case ARG_ADDR_REG32:
        switch(arg2->type){
        case ARG_REG8:
          if (!IS_VALID(ides[OPARG_RM8_REG8]))
            {
              error(cfile, linenum, "Invalid operand.");
              break;
            }
          assert((ides[OPARG_RM8_REG8].modrm & MODRM_ABSENT) == 0);
          assert((ides[OPARG_RM8_REG8].modrm & MODRM_REG) != 0);
          write_instr_modrm_mem(arg2->u.reg, arg1, ides[OPARG_RM8_REG8]);
          break;

        case ARG_REG32:
          if (!IS_VALID(ides[OPARG_RM32_REG32]))
            {
              error(cfile, linenum, "Invalid operand.");
              break;
            }
          assert((ides[OPARG_RM32_REG32].modrm & MODRM_ABSENT) == 0);
          assert((ides[OPARG_RM32_REG32].modrm & MODRM_REG) != 0);
          write_instr_modrm_mem(arg2->u.reg, arg1, ides[OPARG_RM32_REG32]);
          break;

        case ARG_NUM:
          if (arg1->modifier == ARGMOD_BYTE)
            {
              if (IS_VALID(ides[OPARG_MEM8_IMM8]))
                {
                  if (FITS_IN_BYTE(arg2->u.value))
                    {
                      write_instr_modrm_mem(MODRM_MIDDLE(ides[OPARG_MEM8_IMM8]), arg1,
                                            ides[OPARG_MEM8_IMM8]);
                      WRITE_BYTE(arg2->u.value);
                    }
                  else
                    {
                      error(cfile, linenum,
                            "Constant too large - doesn't fit in one byte.");
                    }
                }
              else
                {
                  error(cfile, linenum, "Invalid operand.");
                }
            }
          else if (arg1->modifier == ARGMOD_DWORD)
            {
              if (IS_VALID(ides[OPARG_RM32_IMM8]) && FITS_IN_BYTE(arg2->u.value))
                {
                  assert ((ides[OPARG_RM32_IMM8].modrm & MODRM_ABSENT) == 0);
                  write_instr_modrm_mem(MODRM_MIDDLE(ides[OPARG_RM32_IMM8]), arg1,
                                        ides[OPARG_RM32_IMM8]);
                  WRITE_BYTE(arg2->u.value);
                }
              else if (IS_VALID(ides[OPARG_MEM32_IMM32]))
                {
                  write_instr_modrm_mem(MODRM_MIDDLE(ides[OPARG_MEM32_IMM32]), arg1,
                                        ides[OPARG_MEM32_IMM32]);
                  WRITE_DWORD(arg2->u.value);
                }
              else
                {
                  error(cfile, linenum, "Invalid operand.");
                }
            }
          else
            {
              error(cfile, linenum,
                    "Operand size unspecified. Use `byte' or `dword' modifier.");
            }
          break;

        case ARG_LABEL:
          if (arg1->modifier == ARGMOD_DWORD || arg1->modifier == ARGMOD_NONE)
            {
              if (IS_VALID(ides[OPARG_MEM32_IMM32]))
                {
                  write_instr_modrm_mem(MODRM_MIDDLE(ides[OPARG_MEM32_IMM32]), arg1,
                                        ides[OPARG_MEM32_IMM32]);
                  write_abs_label(arg2->u.label);
                }
              else
                {
                  error(cfile, linenum, "Invalid operand.");
                }
            }
          else
            {
              error(cfile, linenum, "Wrong operand size.");
            }
          break;

        default:
          error(cfile, linenum, "Invalid operand.");
          break;
        };
        break;

      default:
        error(cfile, linenum, "Invalid operand.");
        break;
      };
    } /* end if */
}

void translator_init()
{
  /**** ADD ****/

  opinstr[OP_ADD].arg0_valid = 0;
  opinstr[OP_ADD].arg1_valid = 0;
  opinstr[OP_ADD].arg2_valid = 1;
  opinstr[OP_ADD].arg1_rel_valid = 0;

  opinstr[OP_ADD].arg2[OPARG_RM8_REG8].code = 0x00;
  opinstr[OP_ADD].arg2[OPARG_RM8_REG8].modrm = MODRM_REG;

  opinstr[OP_ADD].arg2[OPARG_REG8_RM8].code = 0x02;
  opinstr[OP_ADD].arg2[OPARG_REG8_RM8].modrm = MODRM_REG;

  opinstr[OP_ADD].arg2[OPARG_REG8_IMM8].code = 0x80;
  opinstr[OP_ADD].arg2[OPARG_REG8_IMM8].modrm = 0;

  opinstr[OP_ADD].arg2[OPARG_MEM8_IMM8].code = 0x80;
  opinstr[OP_ADD].arg2[OPARG_MEM8_IMM8].modrm = 0;

  opinstr[OP_ADD].arg2[OPARG_RM32_REG32].code = 0x01;
  opinstr[OP_ADD].arg2[OPARG_RM32_REG32].modrm = MODRM_REG;

  opinstr[OP_ADD].arg2[OPARG_REG32_RM32].code = 0x03;
  opinstr[OP_ADD].arg2[OPARG_REG32_RM32].modrm = MODRM_REG;

  opinstr[OP_ADD].arg2[OPARG_REG32_IMM32].code = 0x81;
  opinstr[OP_ADD].arg2[OPARG_REG32_IMM32].modrm = 0;

  opinstr[OP_ADD].arg2[OPARG_MEM32_IMM32].code = 0x81;
  opinstr[OP_ADD].arg2[OPARG_MEM32_IMM32].modrm = 0;

  opinstr[OP_ADD].arg2[OPARG_RM32_IMM8].code = 0x83;
  opinstr[OP_ADD].arg2[OPARG_RM32_IMM8].modrm = 0;

  opinstr[OP_ADD].arg2[OPARG_AL_IMM8].code = 0x04;
  opinstr[OP_ADD].arg2[OPARG_AL_IMM8].modrm = MODRM_ABSENT;

  opinstr[OP_ADD].arg2[OPARG_EAX_IMM32].code = 0x05;
  opinstr[OP_ADD].arg2[OPARG_EAX_IMM32].modrm = MODRM_ABSENT;


  /**** SUB ****/

  opinstr[OP_SUB].arg0_valid = 0;
  opinstr[OP_SUB].arg1_valid = 0;
  opinstr[OP_SUB].arg2_valid = 1;
  opinstr[OP_SUB].arg1_rel_valid = 0;

  opinstr[OP_SUB].arg2[OPARG_RM8_REG8].code = 0x28;
  opinstr[OP_SUB].arg2[OPARG_RM8_REG8].modrm = MODRM_REG;

  opinstr[OP_SUB].arg2[OPARG_REG8_RM8].code = 0x2A;
  opinstr[OP_SUB].arg2[OPARG_REG8_RM8].modrm = MODRM_REG;

  opinstr[OP_SUB].arg2[OPARG_REG8_IMM8].code = 0x80;
  opinstr[OP_SUB].arg2[OPARG_REG8_IMM8].modrm = 5;

  opinstr[OP_SUB].arg2[OPARG_MEM8_IMM8].code = 0x80;
  opinstr[OP_SUB].arg2[OPARG_MEM8_IMM8].modrm = 5;

  opinstr[OP_SUB].arg2[OPARG_RM32_REG32].code = 0x29;
  opinstr[OP_SUB].arg2[OPARG_RM32_REG32].modrm = MODRM_REG;

  opinstr[OP_SUB].arg2[OPARG_REG32_RM32].code = 0x2B;
  opinstr[OP_SUB].arg2[OPARG_REG32_RM32].modrm = MODRM_REG;

  opinstr[OP_SUB].arg2[OPARG_REG32_IMM32].code = 0x81;
  opinstr[OP_SUB].arg2[OPARG_REG32_IMM32].modrm = 5;

  opinstr[OP_SUB].arg2[OPARG_MEM32_IMM32].code = 0x81;
  opinstr[OP_SUB].arg2[OPARG_MEM32_IMM32].modrm = 5;

  opinstr[OP_SUB].arg2[OPARG_RM32_IMM8].code = 0x83;
  opinstr[OP_SUB].arg2[OPARG_RM32_IMM8].modrm = 5;

  opinstr[OP_SUB].arg2[OPARG_AL_IMM8].code = 0x2C;
  opinstr[OP_SUB].arg2[OPARG_AL_IMM8].modrm = MODRM_ABSENT;

  opinstr[OP_SUB].arg2[OPARG_EAX_IMM32].code = 0x2D;
  opinstr[OP_SUB].arg2[OPARG_EAX_IMM32].modrm = MODRM_ABSENT;


  /**** MOV ****/

  opinstr[OP_MOV].arg0_valid = 0;
  opinstr[OP_MOV].arg1_valid = 0;
  opinstr[OP_MOV].arg2_valid = 1;
  opinstr[OP_MOV].arg1_rel_valid = 0;

  opinstr[OP_MOV].arg2[OPARG_RM8_REG8].code = 0x88;
  opinstr[OP_MOV].arg2[OPARG_RM8_REG8].modrm = MODRM_REG;

  opinstr[OP_MOV].arg2[OPARG_REG8_RM8].code = 0x8A;
  opinstr[OP_MOV].arg2[OPARG_REG8_RM8].modrm = MODRM_REG;

  opinstr[OP_MOV].arg2[OPARG_REG8_IMM8].code = 0xB0;
  opinstr[OP_MOV].arg2[OPARG_REG8_IMM8].modrm = MODRM_ABSENT;

  opinstr[OP_MOV].arg2[OPARG_MEM8_IMM8].code = 0xC6;
  opinstr[OP_MOV].arg2[OPARG_MEM8_IMM8].modrm = 0;

  opinstr[OP_MOV].arg2[OPARG_RM32_REG32].code = 0x89;
  opinstr[OP_MOV].arg2[OPARG_RM32_REG32].modrm = MODRM_REG;

  opinstr[OP_MOV].arg2[OPARG_REG32_RM32].code = 0x8B;
  opinstr[OP_MOV].arg2[OPARG_REG32_RM32].modrm = MODRM_REG;

  opinstr[OP_MOV].arg2[OPARG_REG32_IMM32].code = 0xB8;
  opinstr[OP_MOV].arg2[OPARG_REG32_IMM32].modrm = MODRM_ABSENT;

  opinstr[OP_MOV].arg2[OPARG_MEM32_IMM32].code = 0xC7;
  opinstr[OP_MOV].arg2[OPARG_MEM32_IMM32].modrm = 0;

  opinstr[OP_MOV].arg2[OPARG_RM32_IMM8].code = 0;
  opinstr[OP_MOV].arg2[OPARG_RM32_IMM8].modrm = OPARG_INVALID;

  opinstr[OP_MOV].arg2[OPARG_AL_IMM8].code = 0;
  opinstr[OP_MOV].arg2[OPARG_AL_IMM8].modrm = OPARG_INVALID;

  opinstr[OP_MOV].arg2[OPARG_EAX_IMM32].code = 0;
  opinstr[OP_MOV].arg2[OPARG_EAX_IMM32].modrm = OPARG_INVALID;


  /**** CMP ****/

  opinstr[OP_CMP].arg0_valid = 0;
  opinstr[OP_CMP].arg1_valid = 0;
  opinstr[OP_CMP].arg2_valid = 1;
  opinstr[OP_CMP].arg1_rel_valid = 0;

  opinstr[OP_CMP].arg2[OPARG_RM8_REG8].code = 0x38;
  opinstr[OP_CMP].arg2[OPARG_RM8_REG8].modrm = MODRM_REG;

  opinstr[OP_CMP].arg2[OPARG_REG8_RM8].code = 0x3A;
  opinstr[OP_CMP].arg2[OPARG_REG8_RM8].modrm = MODRM_REG;

  opinstr[OP_CMP].arg2[OPARG_REG8_IMM8].code = 0x80;
  opinstr[OP_CMP].arg2[OPARG_REG8_IMM8].modrm = 7;

  opinstr[OP_CMP].arg2[OPARG_MEM8_IMM8].code = 0x80;
  opinstr[OP_CMP].arg2[OPARG_MEM8_IMM8].modrm = 7;

  opinstr[OP_CMP].arg2[OPARG_RM32_REG32].code = 0x39;
  opinstr[OP_CMP].arg2[OPARG_RM32_REG32].modrm = MODRM_REG;

  opinstr[OP_CMP].arg2[OPARG_REG32_RM32].code = 0x3B;
  opinstr[OP_CMP].arg2[OPARG_REG32_RM32].modrm = MODRM_REG;

  opinstr[OP_CMP].arg2[OPARG_REG32_IMM32].code = 0x81;
  opinstr[OP_CMP].arg2[OPARG_REG32_IMM32].modrm = 7;

  opinstr[OP_CMP].arg2[OPARG_MEM32_IMM32].code = 0x81;
  opinstr[OP_CMP].arg2[OPARG_MEM32_IMM32].modrm = 7;

  opinstr[OP_CMP].arg2[OPARG_RM32_IMM8].code = 0x83;
  opinstr[OP_CMP].arg2[OPARG_RM32_IMM8].modrm = 7;

  opinstr[OP_CMP].arg2[OPARG_AL_IMM8].code = 0x3C;
  opinstr[OP_CMP].arg2[OPARG_AL_IMM8].modrm = MODRM_ABSENT;

  opinstr[OP_CMP].arg2[OPARG_EAX_IMM32].code = 0x3D;
  opinstr[OP_CMP].arg2[OPARG_EAX_IMM32].modrm = MODRM_ABSENT;


  /**** MUL ****/

  opinstr[OP_MUL].arg0_valid = 0;
  opinstr[OP_MUL].arg1_valid = 1;
  opinstr[OP_MUL].arg2_valid = 0;
  opinstr[OP_MUL].arg1_rel_valid = 0;

  opinstr[OP_MUL].arg1[OPARG_REG8].code = 0xF6;
  opinstr[OP_MUL].arg1[OPARG_REG8].modrm = 4;

  opinstr[OP_MUL].arg1[OPARG_REG32].code = 0xF7;
  opinstr[OP_MUL].arg1[OPARG_REG32].modrm = 4;

  opinstr[OP_MUL].arg1[OPARG_MEM8].code = 0xF6;
  opinstr[OP_MUL].arg1[OPARG_MEM8].modrm = 4;

  opinstr[OP_MUL].arg1[OPARG_MEM32].code = 0xF7;
  opinstr[OP_MUL].arg1[OPARG_MEM32].modrm = 4;

  opinstr[OP_MUL].arg1[OPARG_IMM8].code = 0;
  opinstr[OP_MUL].arg1[OPARG_IMM8].modrm = OPARG_INVALID;

  opinstr[OP_MUL].arg1[OPARG_IMM32].code = 0;
  opinstr[OP_MUL].arg1[OPARG_IMM32].modrm = OPARG_INVALID;


  /**** DIV ****/

  opinstr[OP_DIV].arg0_valid = 0;
  opinstr[OP_DIV].arg1_valid = 1;
  opinstr[OP_DIV].arg2_valid = 0;
  opinstr[OP_DIV].arg1_rel_valid = 0;

  opinstr[OP_DIV].arg1[OPARG_REG8].code = 0xF6;
  opinstr[OP_DIV].arg1[OPARG_REG8].modrm = 6;

  opinstr[OP_DIV].arg1[OPARG_REG32].code = 0xF7;
  opinstr[OP_DIV].arg1[OPARG_REG32].modrm = 6;

  opinstr[OP_DIV].arg1[OPARG_MEM8].code = 0xF6;
  opinstr[OP_DIV].arg1[OPARG_MEM8].modrm = 6;

  opinstr[OP_DIV].arg1[OPARG_MEM32].code = 0xF7;
  opinstr[OP_DIV].arg1[OPARG_MEM32].modrm = 6;

  opinstr[OP_DIV].arg1[OPARG_IMM8].code = 0;
  opinstr[OP_DIV].arg1[OPARG_IMM8].modrm = OPARG_INVALID;

  opinstr[OP_DIV].arg1[OPARG_IMM32].code = 0;
  opinstr[OP_DIV].arg1[OPARG_IMM32].modrm = OPARG_INVALID;


  /**** PUSH ****/

  opinstr[OP_PUSH].arg0_valid = 0;
  opinstr[OP_PUSH].arg1_valid = 1;
  opinstr[OP_PUSH].arg2_valid = 0;
  opinstr[OP_PUSH].arg1_rel_valid = 0;

  opinstr[OP_PUSH].arg1[OPARG_REG8].code = 0;
  opinstr[OP_PUSH].arg1[OPARG_REG8].modrm = OPARG_INVALID;

  opinstr[OP_PUSH].arg1[OPARG_REG32].code = 0x50;
  opinstr[OP_PUSH].arg1[OPARG_REG32].modrm = MODRM_ABSENT;

  opinstr[OP_PUSH].arg1[OPARG_MEM8].code = 0;
  opinstr[OP_PUSH].arg1[OPARG_MEM8].modrm = OPARG_INVALID;

  opinstr[OP_PUSH].arg1[OPARG_MEM32].code = 0xFF;
  opinstr[OP_PUSH].arg1[OPARG_MEM32].modrm = 6;

  opinstr[OP_PUSH].arg1[OPARG_IMM8].code = 0x6A;
  opinstr[OP_PUSH].arg1[OPARG_IMM8].modrm = MODRM_ABSENT;

  opinstr[OP_PUSH].arg1[OPARG_IMM32].code = 0x68;
  opinstr[OP_PUSH].arg1[OPARG_IMM32].modrm = MODRM_ABSENT;


  /**** POP ****/

  opinstr[OP_POP].arg0_valid = 0;
  opinstr[OP_POP].arg1_valid = 1;
  opinstr[OP_POP].arg2_valid = 0;
  opinstr[OP_POP].arg1_rel_valid = 0;

  opinstr[OP_POP].arg1[OPARG_REG8].code = 0;
  opinstr[OP_POP].arg1[OPARG_REG8].modrm = OPARG_INVALID;

  opinstr[OP_POP].arg1[OPARG_REG32].code = 0x58;
  opinstr[OP_POP].arg1[OPARG_REG32].modrm = MODRM_ABSENT;

  opinstr[OP_POP].arg1[OPARG_MEM8].code = 0;
  opinstr[OP_POP].arg1[OPARG_MEM8].modrm = OPARG_INVALID;

  opinstr[OP_POP].arg1[OPARG_MEM32].code = 0x8F;
  opinstr[OP_POP].arg1[OPARG_MEM32].modrm = 6;

  opinstr[OP_POP].arg1[OPARG_IMM8].code = 0;
  opinstr[OP_POP].arg1[OPARG_IMM8].modrm = OPARG_INVALID;

  opinstr[OP_POP].arg1[OPARG_IMM32].code = 0;
  opinstr[OP_POP].arg1[OPARG_IMM32].modrm = OPARG_INVALID;


  /**** INT ****/

  opinstr[OP_INT].arg0_valid = 0;
  opinstr[OP_INT].arg1_valid = 1;
  opinstr[OP_INT].arg2_valid = 0;
  opinstr[OP_INT].arg1_rel_valid = 0;

  opinstr[OP_INT].arg1[OPARG_REG8].code = 0;
  opinstr[OP_INT].arg1[OPARG_REG8].modrm = OPARG_INVALID;

  opinstr[OP_INT].arg1[OPARG_REG32].code = 0;
  opinstr[OP_INT].arg1[OPARG_REG32].modrm = OPARG_INVALID;

  opinstr[OP_INT].arg1[OPARG_MEM8].code = 0;
  opinstr[OP_INT].arg1[OPARG_MEM8].modrm = OPARG_INVALID;

  opinstr[OP_INT].arg1[OPARG_MEM32].code = 0;
  opinstr[OP_INT].arg1[OPARG_MEM32].modrm = OPARG_INVALID;

  opinstr[OP_INT].arg1[OPARG_IMM8].code = 0xCD;
  opinstr[OP_INT].arg1[OPARG_IMM8].modrm = MODRM_ABSENT;

  opinstr[OP_INT].arg1[OPARG_IMM32].code = 0;
  opinstr[OP_INT].arg1[OPARG_IMM32].modrm = OPARG_INVALID;


  /**** JE ****/

  opinstr[OP_JE].arg0_valid = 0;
  opinstr[OP_JE].arg1_valid = 0;
  opinstr[OP_JE].arg2_valid = 0;
  opinstr[OP_JE].arg1_rel_valid = 1;

  opinstr[OP_JE].arg1[OPARG_REL8].code = 0x70 + 4;
  opinstr[OP_JE].arg1[OPARG_REL8].modrm = MODRM_ABSENT;

  opinstr[OP_JE].arg1[OPARG_REL32].code = 0x80 + 4;
  opinstr[OP_JE].arg1[OPARG_REL32].modrm = OPARG_PREFIX_0F;


  /**** JNE ****/

  opinstr[OP_JNE].arg0_valid = 0;
  opinstr[OP_JNE].arg1_valid = 0;
  opinstr[OP_JNE].arg2_valid = 0;
  opinstr[OP_JNE].arg1_rel_valid = 1;

  opinstr[OP_JNE].arg1[OPARG_REL8].code = 0x70 + 5;
  opinstr[OP_JNE].arg1[OPARG_REL8].modrm = MODRM_ABSENT;

  opinstr[OP_JNE].arg1[OPARG_REL32].code = 0x80 + 5;
  opinstr[OP_JNE].arg1[OPARG_REL32].modrm = OPARG_PREFIX_0F;


  /**** JL ****/

  opinstr[OP_JL].arg0_valid = 0;
  opinstr[OP_JL].arg1_valid = 0;
  opinstr[OP_JL].arg2_valid = 0;
  opinstr[OP_JL].arg1_rel_valid = 1;

  opinstr[OP_JL].arg1[OPARG_REL8].code = 0x70 + 12;
  opinstr[OP_JL].arg1[OPARG_REL8].modrm = MODRM_ABSENT;

  opinstr[OP_JL].arg1[OPARG_REL32].code = 0x80 + 12;
  opinstr[OP_JL].arg1[OPARG_REL32].modrm = OPARG_PREFIX_0F;


  /**** JLE ****/

  opinstr[OP_JLE].arg0_valid = 0;
  opinstr[OP_JLE].arg1_valid = 0;
  opinstr[OP_JLE].arg2_valid = 0;
  opinstr[OP_JLE].arg1_rel_valid = 1;

  opinstr[OP_JLE].arg1[OPARG_REL8].code = 0x70 + 14;
  opinstr[OP_JLE].arg1[OPARG_REL8].modrm = MODRM_ABSENT;

  opinstr[OP_JLE].arg1[OPARG_REL32].code = 0x80 + 14;
  opinstr[OP_JLE].arg1[OPARG_REL32].modrm = OPARG_PREFIX_0F;


  /**** JG ****/

  opinstr[OP_JG].arg0_valid = 0;
  opinstr[OP_JG].arg1_valid = 0;
  opinstr[OP_JG].arg2_valid = 0;
  opinstr[OP_JG].arg1_rel_valid = 1;

  opinstr[OP_JG].arg1[OPARG_REL8].code = 0x70 + 15;
  opinstr[OP_JG].arg1[OPARG_REL8].modrm = MODRM_ABSENT;

  opinstr[OP_JG].arg1[OPARG_REL32].code = 0x80 + 15;
  opinstr[OP_JG].arg1[OPARG_REL32].modrm = OPARG_PREFIX_0F;


  /**** JGE ****/

  opinstr[OP_JGE].arg0_valid = 0;
  opinstr[OP_JGE].arg1_valid = 0;
  opinstr[OP_JGE].arg2_valid = 0;
  opinstr[OP_JGE].arg1_rel_valid = 1;

  opinstr[OP_JGE].arg1[OPARG_REL8].code = 0x70 + 13;
  opinstr[OP_JGE].arg1[OPARG_REL8].modrm = MODRM_ABSENT;

  opinstr[OP_JGE].arg1[OPARG_REL32].code = 0x80 + 13;
  opinstr[OP_JGE].arg1[OPARG_REL32].modrm = OPARG_PREFIX_0F;


  /**** JMP ****/

  opinstr[OP_JMP].arg0_valid = 0;
  opinstr[OP_JMP].arg1_valid = 0;
  opinstr[OP_JMP].arg2_valid = 0;
  opinstr[OP_JMP].arg1_rel_valid = 1;

  opinstr[OP_JMP].arg1[OPARG_REL8].code = 0xEB;
  opinstr[OP_JMP].arg1[OPARG_REL8].modrm = MODRM_ABSENT;

  opinstr[OP_JMP].arg1[OPARG_REL32].code = 0xE9;
  opinstr[OP_JMP].arg1[OPARG_REL32].modrm = MODRM_ABSENT;


  /**** CALL ****/

  opinstr[OP_CALL].arg0_valid = 0;
  opinstr[OP_CALL].arg1_valid = 0;
  opinstr[OP_CALL].arg2_valid = 0;
  opinstr[OP_CALL].arg1_rel_valid = 1;

  opinstr[OP_CALL].arg1[OPARG_REL8].code = 0;
  opinstr[OP_CALL].arg1[OPARG_REL8].modrm = OPARG_INVALID;

  opinstr[OP_CALL].arg1[OPARG_REL32].code = 0xE8;
  opinstr[OP_CALL].arg1[OPARG_REL32].modrm = MODRM_ABSENT;


  /**** RET ****/

  opinstr[OP_RET].arg0_valid = 1;
  opinstr[OP_RET].arg1_valid = 0;
  opinstr[OP_RET].arg2_valid = 0;
  opinstr[OP_RET].arg1_rel_valid = 0;

  opinstr[OP_RET].arg0.code = 0xC3;
  opinstr[OP_RET].arg0.modrm = MODRM_ABSENT;
}

int translate(const char *infile, const char *outfile)
{
  instr_t *instr;
  entry_t *pe;
  int i;
  fwd_label_t *fwd;
  ref_t *r;
  ref_t *rn;
  arg_t *arg;
  char *p;

  /********************************************************/

  entry_t entry_eax = { SYM_REG32, { REG_EAX } };
  entry_t entry_ebx = { SYM_REG32, { REG_EBX } };
  entry_t entry_ecx = { SYM_REG32, { REG_ECX } };
  entry_t entry_edx = { SYM_REG32, { REG_EDX } };
  entry_t entry_esi = { SYM_REG32, { REG_ESI } };
  entry_t entry_edi = { SYM_REG32, { REG_EDI } };
  entry_t entry_ebp = { SYM_REG32, { REG_EBP } };
  entry_t entry_esp = { SYM_REG32, { REG_ESP } };
  entry_t entry_al = { SYM_REG8, { REG_AL } };
  entry_t entry_ah = { SYM_REG8, { REG_AH } };
  entry_t entry_bl = { SYM_REG8, { REG_BL } };
  entry_t entry_bh = { SYM_REG8, { REG_BH } };
  entry_t entry_cl = { SYM_REG8, { REG_CL } };
  entry_t entry_ch = { SYM_REG8, { REG_CH } };
  entry_t entry_dl = { SYM_REG8, { REG_DL } };
  entry_t entry_dh = { SYM_REG8, { REG_DH } };
  entry_t entry_mov = { SYM_OPCODE, { OP_MOV } };
  entry_t entry_add = { SYM_OPCODE, { OP_ADD } };
  entry_t entry_sub = { SYM_OPCODE, { OP_SUB } };
  entry_t entry_mul = { SYM_OPCODE, { OP_MUL } };
  entry_t entry_div = { SYM_OPCODE, { OP_DIV } };
  entry_t entry_cmp = { SYM_OPCODE, { OP_CMP } };
  entry_t entry_je = { SYM_OPCODE, { OP_JE } };
  entry_t entry_jne = { SYM_OPCODE, { OP_JNE } };
  entry_t entry_jg = { SYM_OPCODE, { OP_JG } };
  entry_t entry_jl = { SYM_OPCODE, { OP_JL } };
  entry_t entry_jge = { SYM_OPCODE, { OP_JGE } };
  entry_t entry_jle = { SYM_OPCODE, { OP_JLE } };
  entry_t entry_jmp = { SYM_OPCODE, { OP_JMP } };
  entry_t entry_int = { SYM_OPCODE, { OP_INT } };
  entry_t entry_call = { SYM_OPCODE, { OP_CALL } };
  entry_t entry_ret = { SYM_OPCODE, { OP_RET } };
  entry_t entry_push = { SYM_OPCODE, { OP_PUSH } };
  entry_t entry_pop = { SYM_OPCODE, { OP_POP } };
  entry_t entry_db = { SYM_OPCODE, { OP_DB } };
  entry_t entry_dd = { SYM_OPCODE, { OP_DD } };
  entry_t entry_section = { SYM_OPCODE, { OP_SECTION } };
  entry_t entry_extern = { SYM_OPCODE, { OP_EXTERN } };
  entry_t entry_global = { SYM_OPCODE, { OP_GLOBAL } };
  entry_t entry_near = { SYM_ARGMOD, { ARGMOD_NEAR } };
  entry_t entry_byte = { SYM_ARGMOD, { ARGMOD_BYTE } };
  entry_t entry_dword = { SYM_ARGMOD, { ARGMOD_DWORD } };

  symtab_init();

  symtab_insert("eax", &entry_eax);
  symtab_insert("ebx", &entry_ebx);
  symtab_insert("ecx", &entry_ecx);
  symtab_insert("edx", &entry_edx);
  symtab_insert("esi", &entry_esi);
  symtab_insert("edi", &entry_edi);
  symtab_insert("ebp", &entry_ebp);
  symtab_insert("esp", &entry_esp);
  symtab_insert("al", &entry_al);
  symtab_insert("ah", &entry_ah);
  symtab_insert("bl", &entry_bl);
  symtab_insert("bh", &entry_bh);
  symtab_insert("cl", &entry_cl);
  symtab_insert("ch", &entry_ch);
  symtab_insert("dl", &entry_dl);
  symtab_insert("dh", &entry_dh);

  symtab_insert("mov", &entry_mov);
  symtab_insert("add", &entry_add);
  symtab_insert("sub", &entry_sub);
  symtab_insert("div", &entry_div);
  symtab_insert("mul", &entry_mul);
  symtab_insert("cmp", &entry_cmp);
  symtab_insert("je", &entry_je);
  symtab_insert("jne", &entry_jne);
  symtab_insert("jl", &entry_jl);
  symtab_insert("jle", &entry_jle);
  symtab_insert("jg", &entry_jg);
  symtab_insert("jge", &entry_jge);
  symtab_insert("jmp", &entry_jmp);
  symtab_insert("call", &entry_call);
  symtab_insert("ret", &entry_ret);
  symtab_insert("int", &entry_int);
  symtab_insert("push", &entry_push);
  symtab_insert("pop", &entry_pop);
  symtab_insert("db", &entry_db);
  symtab_insert("dd", &entry_dd);
  symtab_insert("section", &entry_section);
  symtab_insert("extern", &entry_extern);
  symtab_insert("global", &entry_global);

  symtab_insert("near", &entry_near);
  symtab_insert("byte", &entry_byte);
  symtab_insert("dword", &entry_dword);

  /***********************************************/

  errors = 0;
  forward_labels = NULL;
  cfile = infile;

  r_top = -1;
  se_top = -1;
  s_top = 0;

  /* allocate sections */
  for (i = 0; i < MAX_SECTIONS; ++i)
    {
      sec_offset[i] = 0;
      sec_max_size[i] = 512;
      sec[i] = (char*) xmalloc(sec_max_size[i]);
    }

  open_file(infile);
  csec = SEC_TEXT;


  /* main loop */
  while ((instr = get_instr()) != NULL)
    {
      if (sec_offset[csec] + MAX_INSTR_LEN >= sec_max_size[csec])
        {
          sec_max_size[csec] *= 2;
          sec[csec] = xrealloc(sec[csec], sec_max_size[csec]);
        }

      /* process label */
      if (instr->label[0] != '\0')
        {
          add_label(instr->label);
        }

      /* process instruction */
      switch(instr->opcode){
      case OP_DB:
        arg = instr->arg;
        if (arg == NULL)
          {
            error(cfile, linenum, "Expected at least one argument.");
          }
        while (arg != NULL)
          {
            if (arg->type == ARG_STR)
              {
                if (sec_offset[csec] + MAX_STR_LEN >= sec_max_size[csec])
                  {
                    sec_max_size[csec] *= 2;
                    sec[csec] = xrealloc(sec[csec], sec_max_size[csec]);
                  }
                p = arg->u.str;
                while (*p != 0)
                  {
                    sec[csec][sec_offset[csec]++] = *(p++);
                  }

              }
            else if (arg->type == ARG_NUM)
              {
                if (sec_offset[csec] + 1 >= sec_max_size[csec])
                  {
                    sec_max_size[csec] *= 2;
                    sec[csec] = xrealloc(sec[csec], sec_max_size[csec]);
                  }
                if (FITS_IN_BYTE(arg->u.value))
                  {
                    WRITE_BYTE(arg->u.value);
                  }
                else
                  {
                    error(cfile, linenum,
                          "Constant too large - doesn't fit in one byte.");
                  }
              }
            else
              {
                error(cfile, linenum, "Invalid argument.");
              }
            arg = arg->next;
          } /* end while (arg != NULL) */
        break;

      case OP_DD:
        arg = instr->arg;
        if (arg == NULL)
          {
            error(cfile, linenum, "Expected at least one argument.");
          }
        while (arg != NULL)
          {
            if (arg->type == ARG_NUM)
              {
                if (sec_offset[csec] + 4 >= sec_max_size[csec])
                  {
                    sec_max_size[csec] *= 2;
                    sec[csec] = xrealloc(sec[csec], sec_max_size[csec]);
                  }
                WRITE_DWORD(arg->u.value);
              }
            else
              {
                error(cfile, linenum, "Invalid argument.");
              }
            arg = arg->next;
          }
        break;

      case OP_GLOBAL:
        arg = instr->arg;
        if (arg == NULL)
          {
            error(cfile, linenum, "Expected at least one argument.");
          }
        while (arg != NULL)
          {
            if (arg->type == ARG_LABEL)
              {
                pe = symtab_search(arg->u.label);
                if (pe == NULL)
                  {
                    fwd = (fwd_label_t*) xmalloc(sizeof(fwd_label_t));
                    fwd->ref = NULL;
                    fwd->global = 1;
                    fwd->label = xstrdup(arg->u.label);
                    ++se_top;
                    symtab_entries[se_top].type = SYM_FORWARD_LABEL;
                    symtab_entries[se_top].u.data = fwd;
                    symtab_insert(fwd->label, &symtab_entries[se_top]);
                  }
                else
                  {
                    switch(pe->type){
                    case SYM_LABEL:
                      assert (pe->u.value <= s_top);
                      symbols[pe->u.value].global = 1;
                      break;

                    case SYM_FORWARD_LABEL:
                      fwd = (fwd_label_t*) pe->u.data;
                      fwd->global = 1;
                      break;

                    default:
                      error(cfile, linenum,
                            "The global pseudoinstruction may be applied to labels only.");
                      break;
                    };
                  }
              }
            else
              {
                error(cfile, linenum, "Invalid argument.");
              }
            arg = arg->next;
          }
        break;

      case OP_EXTERN:
        arg = instr->arg;
        if (arg == NULL)
          {
            error(cfile, linenum, "Expected at least one argument.");
          }
        while (arg != NULL)
          {
            if (arg->type == ARG_LABEL)
              {
                pe = symtab_search(arg->u.label);
                if (pe == NULL)
                  {
                    ++s_top;
                    if (s_top >= MAX_SYMBOLS)
                      {
                        fatal("Too many symbols.");
                      }
                    symbols[s_top].name = xstrdup(arg->u.label);
                    symbols[s_top].value = 0;
                    symbols[s_top].section = SEC_EXTERN;
                    symbols[s_top].global = 1;
                    ++se_top;
                    symtab_entries[se_top].type = SYM_EXTERN;
                    symtab_entries[se_top].u.value = s_top;
                    symtab_insert(symbols[s_top].name, &symtab_entries[se_top]);
                  }
                else
                  {
                    if (pe->type == SYM_FORWARD_LABEL)
                      {
                        error(cfile, linenum,
                              "External symbols must be defined before used.");
                      }
                    else
                      {
                        error(cfile, linenum, "Duplicate identifier.");
                      }
                  }
              }
            else
              {
                error(cfile, linenum, "Invalid argument.");
              }
            arg = arg->next;
          }
        break;

      case OP_SECTION:
        arg = instr->arg;
        if (arg == NULL)
          {
            error(cfile, linenum, "Expected section name.");
            break;
          }
        if (arg->next != NULL)
          {
            error(cfile, linenum, "Too many arguments.");
            break;
          }
        if (arg->type != ARG_DOT_IDENT)
          {
            error(cfile, linenum, "Expected section name.");
            break;
          }
        if (strcmp(arg->u.label, "data") == 0)
          {
            csec = SEC_DATA;
          }
        else if (strcmp(arg->u.label, "text") == 0)
          {
            csec = SEC_TEXT;
          }
        else
          {
            error(cfile, linenum, "Invalid section name.");
          }
        break;

      case OP_NONE:
        /* No instruction - do nothing. */
        break;

      default:
        generic_instr_process(instr);
        break;
      };

      free_instr(instr);

    } /* end main loop */

  /* check for references to undefined labels */
  while (forward_labels != NULL)
    {
      /* forward_labels->ref may be NULL if the label was only
         declared global, but never used  */
      r = forward_labels->ref;
      while (r != NULL)
        {
          error(cfile, r->linenum, "Undefined identifier.");
          rn = r->next;
          free(r);
          r = rn;
        }
      free(forward_labels->label);
      fwd = forward_labels->next;
      free(forward_labels);
      forward_labels = fwd;
    }

  /* write output */

  if (errors == 0)
    {
      write_elf_file(outfile,
                     sec[SEC_TEXT], sec_offset[SEC_TEXT],
                     sec[SEC_DATA], sec_offset[SEC_DATA],
                     symbols + 1, s_top,
                     relocs, r_top + 1);
    }
  else
    {
      fprintf(stderr, "There were %d errors. Output not written.\n", errors);
    }

  /* cleanup */

  symtab_cleanup();

  for (i = 0; i <= s_top; ++i)
    {
      free(symbols[i].name);
    }
  for (i = 0; i < MAX_SECTIONS; ++i)
    {
      free(sec[i]);
    }

  if (errors == 0)
    {
      return 1;
    }
  else
    {
      return 0;
    }
}

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decode.h"
#include "print.h"


void print_ctrl(bool runs, bool is_valid) {
  printf("   : %c-%c ", runs ? 'R' : '-', is_valid ? 'V' : '-');
}

const char* alu_ops[16] = {
  "ADD ", "SUB ", "AND ", "OR  ", 
  "XOR ", "-   ", "SAR ", "SAL ",
  "SHR ", "-   ", "-   ", "-   ",
  "-   ", "-   ", "-   ", "-   "
};

const char* cflow_ops[16] = {
  "CBE ", "CBNE", "-   ", "-   ",
  "CBL ", "CBLE", "CBG ", "CBGE",
  "CBA ", "CBAE", "CBB ", "CBBE",
  "-   ", "-   ", "CALL", "JMP "
};

const char* imm_cflow_ops[16] = {
  "CBE ", "CBNE", "-   ", "-   ",
  "CBL ", "CBLE", "CBG ", "CBGE",
  "CBA ", "CBAE", "CBB ", "CBBE",
  "-   ", "-   ", "-   ", "-   "
};

const char* leaq_forms[16] = {
  "-", "LEAQ (s),d", "LEAQ (,z,v),d", "LEAQ (s,z,v),d",
  "LEAQ i,d", "LEAQ i(s),d", "LEAQ i(,z,v),d", "LEAQ i(s,z,v),d",
  "-", "-", "-", "-",
  "-", "-", "-", "-"
};

void print_decoded(val major_op, val minor_op) {
  printf(" %lx%lx  ", major_op.val, minor_op.val);
  if (major_op.val == RETURN_STOP) {
    if (minor_op.val == STOP)              printf("STOP            ");
    else if (minor_op.val == RETURN)       printf("RET s           ");
    else                                   printf("-               ");
  }
  else if (major_op.val == REG_ARITHMETIC) {
                                           printf("%s s,d        ", alu_ops[minor_op.val]);
  }
  else if (major_op.val == REG_MOVQ)       printf("MOVQ s,d        ");
  else if (major_op.val == REG_MOVQ_MEM) {
    if (minor_op.val == 1)                 printf("MOVQ (s)->d     ");
    else if (minor_op.val == 9)            printf("MOVQ d->(s)     ");
    else                                   printf("-               ");
  }
  else if (major_op.val == CFLOW)          printf("%s  s,d,p     ", cflow_ops[minor_op.val]);
  else if (major_op.val == IMM_ARITHMETIC) printf("%s $i,d       ", alu_ops[minor_op.val]);
  else if (major_op.val == IMM_MOVQ)       printf("MOVQ $i,d       ");
  else if (major_op.val == IMM_MOVQ_MEM) {
    if (minor_op.val == 5)                 printf("MOVQ i(s),d     ");
    else if (minor_op.val == 13)           printf("MOVQ d,i(s)     ");
    else                                   printf("-               ");
  }
  else if (major_op.val == IMM_CBRANCH)    printf("%s $i,d,p     ", imm_cflow_ops[minor_op.val]);
  else                                     printf("%-16s", leaq_forms[minor_op.val]);
  printf("    ");
}

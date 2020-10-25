#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "support.h"
#include "wires.h"

// major opcodes
#define RETURN_STOP    0x0
#define REG_ARITHMETIC 0x1
#define REG_MOVQ       0x2
#define REG_MOVQ_MEM   0x3
#define CFLOW          0x4
#define IMM_ARITHMETIC 0x5
#define IMM_MOVQ       0x6
#define IMM_MOVQ_MEM   0x7
#define LEAQ2          0x8
#define LEAQ3          0x9
#define LEAQ6          0xA
#define LEAQ7          0xB
#define IMM_CBRANCH    0xF

// minor opcodes which are not used for alu control
#define STOP 0x0
#define RETURN 0x1
#define JMP 0xF
#define CALL 0xE


typedef struct {
  bool is_return_stop;
  bool is_reg_arithmetic;
  bool is_reg_movq;
  bool is_reg_movq_mem;
  bool is_cflow;
  bool is_imm_arithmetic;
  bool is_imm_movq;
  bool is_imm_movq_mem;
  bool is_leaq2;
  bool is_leaq3;
  bool is_leaq6;
  bool is_leaq7;
  bool is_imm_cbranch;
} decoded_major;

decoded_major decode_major(val major_op);

typedef struct {
  bool is_leaq;
  bool is_move;
  bool is_mem_access;
  bool is_load;
  bool is_store;
  bool is_jmp;
  bool is_call;
  bool is_conditional;
  bool is_stop;
  bool is_return;
  bool is_arithmetic;

  bool use_imm;
  bool reg_wr_enable;
  bool use_agen;
  bool use_next_ip;
  bool use_alu;
  bool use_shifter;
  bool use_direct;
  bool use_s;
  bool use_z;
  bool use_disp;
  bool shift_is_signed;
  bool shift_is_left;
} execute_control;

execute_control full_decode(decoded_major* major, val minor_op);

typedef struct { // represent size of an instruction. Only one member is 'true'
  bool is_2;
  bool is_3;
  bool is_6;
  bool is_7;
  bool is_10;
} size_selector;

size_selector to_size_selector(decoded_major dec);

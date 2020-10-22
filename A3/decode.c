#include "decode.h"

#include "arithmetic.h"
#include "compute.h"



decoded_major decode_major(val major_op) {
  decoded_major result;
  result.is_return_stop = is(RETURN_STOP, major_op);
  result.is_reg_arithmetic = is(REG_ARITHMETIC, major_op);
  result.is_imm_arithmetic = is(IMM_ARITHMETIC, major_op);
  result.is_reg_movq = is(REG_MOVQ, major_op);
  result.is_imm_movq = is(IMM_MOVQ, major_op);
  result.is_reg_movq_mem = is(REG_MOVQ_MEM, major_op);
  result.is_imm_movq_mem = is(IMM_MOVQ_MEM, major_op);
  result.is_cflow = is(CFLOW, major_op);
  result.is_leaq2  = is(LEAQ2, major_op);
  result.is_leaq3  = is(LEAQ3, major_op);
  result.is_leaq6  = is(LEAQ6, major_op);
  result.is_leaq7  = is(LEAQ7, major_op);
  result.is_imm_cbranch = is(IMM_CBRANCH, major_op);
  return result;
}


execute_control full_decode(decoded_major* major, val minor_op) {
  execute_control result;
  // broad categorization of the instruction
  result.is_leaq = major->is_leaq2 || major->is_leaq3 || major->is_leaq6 || major->is_leaq7;
  result.is_move = major->is_reg_movq || major->is_reg_movq_mem  || major->is_imm_movq || major->is_imm_movq_mem;
  result.is_mem_access = major->is_reg_movq_mem || major->is_imm_movq_mem;
  result.is_load = result.is_mem_access && is(0, pick_bits(3, 1, minor_op));
  result.is_store = result.is_mem_access && is(1, pick_bits(3, 1, minor_op));
  result.is_jmp = major->is_cflow && is(JMP, minor_op);
  result.is_call = major->is_cflow && is(CALL, minor_op);
  result.is_conditional = major->is_imm_cbranch || (major->is_cflow && !result.is_jmp && !result.is_call);
  result.is_stop = major->is_return_stop && is(STOP, minor_op);
  result.is_return = major->is_return_stop && is(RETURN, minor_op);

  // setting up operand fetch and register read and write for the datapath:
  result.use_imm = major->is_imm_movq | major->is_imm_arithmetic | major->is_imm_cbranch;

  result.reg_wr_enable = major->is_reg_arithmetic || major->is_imm_arithmetic || result.is_leaq 
    || major->is_reg_movq || major->is_imm_movq || result.is_call;

  // control signals for the compute section:
  // - pick result of compute section
  result.use_agen =       result.is_leaq || result.is_move;
  result.use_next_ip =    result.is_call;
  result.is_arithmetic =  major->is_imm_arithmetic | major->is_reg_arithmetic;
  result.use_shifter =    result.is_arithmetic && (is(SAR, minor_op) || is(SAL, minor_op) || is(SHR, minor_op));
  result.use_direct =     major->is_reg_movq || major->is_imm_movq;
  result.use_alu =        (result.is_arithmetic || result.is_conditional) && !result.use_shifter;

  // - control for the address generator
  result.use_s = (is(1,pick_bits(0,1,minor_op)) && result.use_agen) || major->is_reg_arithmetic || major->is_cflow;
  result.use_z = is(1,pick_bits(1,1,minor_op)) && result.use_agen;
  result.use_disp = (is(1,pick_bits(2,1,minor_op)) && result.use_agen) || major->is_imm_arithmetic || major->is_imm_cbranch;

  // - control for the shifter
  result.shift_is_signed = is(SAR, minor_op) | is(SAL, minor_op);
  result.shift_is_left   = is(SAL, minor_op);
  return result;
}

size_selector to_size_selector(decoded_major dec)
{
  size_selector result;
  result.is_2 = dec.is_return_stop || dec.is_reg_arithmetic || dec.is_reg_movq || dec.is_reg_movq_mem || dec.is_leaq2;
  result.is_3 = dec.is_leaq3;
  result.is_6 = dec.is_imm_arithmetic || dec.is_imm_movq || dec.is_imm_movq_mem || dec.is_cflow || dec.is_leaq6;
  result.is_7 = dec.is_leaq7;
  result.is_10 = dec.is_imm_cbranch;
  return result;
}


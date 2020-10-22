#include "wires.h"


typedef struct {
  bool in;
  bool out;
  bool wr_enable;
} reg_bool;

typedef struct {
  val in;
  val out;
  bool wr_enable;
} reg_val;

typedef struct {  // Registers controlling fetch and initial decode
  reg_val ip;
} fetch_regs;

typedef struct {  // registers on the boundary between fetch and compute
  reg_bool is_valid;
  reg_val major_op;  // major opcode (first 4 bits)
  reg_val minor_op;  // minor opcode (next 4 bits)
  reg_val reg_d;     // register designators
  reg_val reg_s;
  reg_val reg_z;
  reg_val shamt;     // shift amount
  reg_val imm_i;     // first 32 bit immediate
  reg_val imm_p;     // secdond 32 bit immediate
  reg_val next_ip;   // address of next/following instruction
} compute_regs;


typedef struct {   // registers on the boundary between compute and memory access
  reg_bool is_valid;
  reg_bool is_load;
  reg_bool is_store;
  reg_val addr;      // memory address of interest
  reg_val value;     // value to store there (for store)
  reg_val reg_d;     // destination register (for load)
} load_store_regs;

typedef struct {   // signals which indicate events that need to be taken into account
                   // when controlling the pipeline.
  bool data_access_ok;  // data memory access succeeded (or no access was needed or access can be ignored)
  bool insn_access_ok;  // insn memory access succeeded (or no access was needed or access can be ignored)
  bool insn_flow_change_request;
} selected_events;

typedef struct {           // signals control pipeline flow
  bool fetch_runs;         // - instruction fetch registers should be updated
  bool compute_runs;       // - compute stage registers should be updated
  bool load_store_runs;    // - data memory access stage registers should be updated
  bool fetch_valid;        // - the result of instruction fetch is valid
} pipeline_control;

void fetch_clk(fetch_regs* f);
void compute_clk(compute_regs* c);
void load_store_clk(load_store_regs* ls);

pipeline_control control_pipeline(fetch_regs* fetch, compute_regs* compute, load_store_regs* load_store,
                                  selected_events* events);

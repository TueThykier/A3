#include "pipe_ctrl.h"
#include "arithmetic.h"

void fetch_wr_enable(fetch_regs* f, bool enable) {
  f->ip.wr_enable = enable;
}

void compute_wr_enable(compute_regs* c, bool enable) {
  c->is_valid.wr_enable = enable;
  c->major_op.wr_enable = enable;
  c->minor_op.wr_enable = enable;
  c->reg_d.wr_enable = enable;
  c->reg_s.wr_enable = enable;
  c->reg_z.wr_enable = enable;
  c->shamt.wr_enable = enable;
  c->imm_i.wr_enable = enable;
  c->imm_p.wr_enable = enable;
  c->next_ip.wr_enable = enable;
}

void load_store_wr_enable(load_store_regs* ls, bool enable) {
  ls->is_valid.wr_enable = enable;
  ls->is_load.wr_enable = enable;
  ls->is_store.wr_enable = enable;
  ls->addr.wr_enable = enable;
  ls->value.wr_enable = enable;
  ls->reg_d.wr_enable = enable;
}


#define CLK(reg) if (reg.wr_enable) { reg.out = reg.in; }
void fetch_clk(fetch_regs* f) {
  CLK(f->ip);
}

void compute_clk(compute_regs* c) {
  CLK(c->is_valid);
  CLK(c->major_op);
  CLK(c->minor_op);
  CLK(c->reg_d);
  CLK(c->reg_s);
  CLK(c->reg_z);
  CLK(c->shamt);
  CLK(c->imm_i);
  CLK(c->imm_p);
  CLK(c->next_ip);
}

void load_store_clk(load_store_regs* ls) {
  CLK(ls->is_valid);
  CLK(ls->is_load);
  CLK(ls->is_store);
  CLK(ls->addr);
  CLK(ls->value);
  CLK(ls->reg_d);
}

pipeline_control control_pipeline(fetch_regs* fetch, compute_regs* compute, load_store_regs* load_store, 
                                  selected_events* events) {

    pipeline_control result;
    // Hazard detection: compute may need to stall if there is a data hazard
    bool hazard = load_store->is_load.out && load_store->is_valid.out && 
      (same(load_store->reg_d.out, compute->reg_d.out)
       || same(load_store->reg_d.out, compute->reg_s.out)
       || same(load_store->reg_d.out, compute->reg_z.out));

    // Determine which pipeline stages run/stall
    // load_store runs if the memory/cache can deliver (or if there is no access):
    result.load_store_runs = events->data_access_ok;
    load_store_wr_enable(load_store, result.load_store_runs);

    // compute stage runs if next stage can accept an insn and if there is no hazard against a load there
    result.compute_runs = result.load_store_runs && !hazard;
    compute_wr_enable(compute, result.compute_runs);

    // fetch runs if next stage can accept an insn and if memory/cache access was fine
    result.fetch_runs = result.compute_runs && events->insn_access_ok;

    // has the compute stage taken control of the instruction pointer?
    bool compute_overrides = result.compute_runs && events->insn_flow_change_request && compute->is_valid.out;

    // if so, the instructions fetched simultaneously is invalid and must be marked as such
    result.fetch_valid = result.fetch_runs && !compute_overrides;

    // if fetch does not progress with a valid instruction, pass on a "bubble" instead
    compute->is_valid.in = result.fetch_valid;

    // likewise for data memory access
    load_store->is_valid.in = compute->is_valid.out && result.compute_runs;

    fetch_wr_enable(fetch, result.fetch_runs);

    return result;
}

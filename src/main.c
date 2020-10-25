#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "support.h"
#include "wires.h"
#include "arithmetic.h"
#include "memory.h"
#include "registers.h"
#include "decode.h"
#include "compute.h"
#include "pipe_ctrl.h"
#include "print.h"



int main(int argc, char* argv[]) {
    // Check command line parameters.
    if (argc < 2)
        error("missing name of programfile to simulate");

    if (argc < 3)
        error("Missing starting address (in hex notation)");

    /*** SETUP ***/
    // We set up global state through variables that are preserved between
    // cycles.
    fetch_regs fetch;
    compute_regs compute;
    load_store_regs load_store;

    // global signals relevant for control
    selected_events events;

    // set Instruction Pointer, later state is invalid
    compute.is_valid.out = false;
    load_store.is_valid.out = false;

    // Register file:
    reg_p regs = regs_create();

    // Memory:
    // Shared memory for both instructions and data.
    mem_p mem = memory_create();
    memory_read_from_file(mem, argv[1]);

    int start;
    int scan_res = sscanf(argv[2],"%x", &start);
    if (scan_res != 1)
        error("Unable to interpret starting address");

    // We must setup argv from commandline before enabling tracefile
    // validation.
    if (argc > 4) { // one or more additional arguments specified.
        if (strcmp(argv[3],"--") != 0)
            error("3rd arg must be '--' if additional args are provided");
        // arguments beyond '--' are loaded into argv area in memory
        memory_load_argv(mem, argc - 4, argv + 4);
    } else
        memory_load_argv(mem, 0, NULL);

    // memory is now set up correctly, and we can enable tracefile
    // validation if a tracefile has been specified.
    if (argc == 4) { // tracefile specified, hook memories to it
        memory_tracefile(mem, argv[3]);
        regs_tracefile(regs, argv[3]);
    }
    fetch.ip.out = from_int(start);

    // a stop signal for stopping the simulation.
    bool stop = false;

    // We need the clock cycle number to show how far we get
    int cycle_number = 0;
    int insn_number = 0;
    while (!stop) { // for each cycle:

        ///////////////////
        //
        // Fetch
        //
        //////////////////

        // We're fetching 10 bytes in the form of 10 vals with one byte each
        val pc = fetch.ip.out;
        val inst_bytes[10];
        events.insn_access_ok = memory_read_into_buffer(mem, pc, inst_bytes, true);

        // determine the possible next IP's for different instruction sizes
        val next_ip_2 = add(pc, from_int(2));
        val next_ip_3 = add(pc, from_int(3));
        val next_ip_6 = add(pc, from_int(6));
        val next_ip_7 = add(pc, from_int(7));
        val next_ip_10 = add(pc, from_int(10));

        /*** (preliminary) Decode ***/
        val major_op = pick_bits(4,  4, inst_bytes[0]);

        compute.major_op.in = major_op;
        compute.minor_op.in = pick_bits(0,  4, inst_bytes[0]);
        compute.reg_d.in = pick_bits(4, 4, inst_bytes[1]);
        compute.reg_s.in = pick_bits(0, 4, inst_bytes[1]);
        compute.reg_z.in = pick_bits(4, 4, inst_bytes[2]);
        compute.shamt.in = pick_bits(0, 4, inst_bytes[2]);

        decoded_major fetch_major = decode_major(major_op);
        size_selector size_selector = to_size_selector(fetch_major);

        // get ready to select the proper immediate positions within the instruction:
        bool imm_i_pos3 = fetch_major.is_leaq7;  /* all other at position 2 */
        bool imm_p_pos6 = fetch_major.is_imm_cbranch; /* all other at position 2 */

        // pick out immediates at possible offsets
        val imm_offset_2 = or(or(put_bits(0, 8, inst_bytes[2]), put_bits(8,8, inst_bytes[3])),
                              or(put_bits(16, 8, inst_bytes[4]), put_bits(24,8, inst_bytes[5])));
        val imm_offset_3 = or(or(put_bits(0, 8, inst_bytes[3]), put_bits(8,8, inst_bytes[4])),
                              or(put_bits(16, 8, inst_bytes[5]), put_bits(24,8, inst_bytes[6])));
        val imm_offset_6 = or(or(put_bits(0, 8, inst_bytes[6]), put_bits(8,8, inst_bytes[7])),
                              or(put_bits(16, 8, inst_bytes[8]), put_bits(24,8, inst_bytes[9])));

        // select immediates for later use
        val imm_i = or(use_if( !imm_i_pos3, imm_offset_2), use_if( imm_i_pos3, imm_offset_3));
        val imm_p = or(use_if( !imm_p_pos6, imm_offset_2), use_if( imm_p_pos6, imm_offset_6));
        compute.imm_i.in = imm_i;
        compute.imm_p.in = imm_p;

        // pre-compute possible next IP
        val next_ip = or5(use_if(size_selector.is_2, next_ip_2),
                          use_if(size_selector.is_3, next_ip_3),
                          use_if(size_selector.is_6, next_ip_6),
                          use_if(size_selector.is_7, next_ip_7),
                          use_if(size_selector.is_10, next_ip_10));
        compute.next_ip.in = next_ip;





        ///////////////////
        //
        // Compute
        //
        ///////////////////

        decoded_major major = decode_major(compute.major_op.out);
        val minor_op = compute.minor_op.out;
        execute_control dp_ctrl = full_decode(&major, minor_op);
        // - control for the ALU.
        val alu_ctrl = minor_op;



        // Datapath:
        //
        val sext_imm_i = sign_extend(31, compute.imm_i.out);
        val sext_imm_p = sign_extend(31, compute.imm_p.out);
        // read registers
        val reg_out_d = reg_read(regs, compute.reg_d.out);
        val reg_out_z = reg_read(regs, compute.reg_z.out);
        val reg_out_s = reg_read(regs, compute.reg_s.out);
        // op_b is snd arg to most arithmetic and can be either an immediate or a register value
        val op_b = or(use_if(dp_ctrl.use_imm, sext_imm_i), use_if(!dp_ctrl.use_imm, reg_out_s));

        // perform calculations in parallel, then pick result
        val agen_result = address_generate(reg_out_z, reg_out_s, sext_imm_i,
                           compute.shamt.out, dp_ctrl.use_z, dp_ctrl.use_s, dp_ctrl.use_disp);
        val alu_result = alu_execute(minor_op, reg_out_d, op_b);
        val shifter_result = shifter(dp_ctrl.shift_is_left, dp_ctrl.shift_is_signed, reg_out_d, op_b);
        bool condition_met = comparator(alu_ctrl, reg_out_d, op_b);
        events.insn_flow_change_request = (condition_met && dp_ctrl.is_conditional) 
          || dp_ctrl.is_jmp || dp_ctrl.is_call || dp_ctrl.is_return;
        val compute_result = or5(use_if(dp_ctrl.use_agen, agen_result),
                                 use_if(dp_ctrl.use_next_ip, compute.next_ip.out),
                                 use_if(dp_ctrl.use_shifter, shifter_result),
                                 use_if(dp_ctrl.use_direct, op_b),
                                 use_if(dp_ctrl.use_alu, alu_result));
        // the compute stage may pick a control flow destination:
        val compute_next_ip = or(use_if(!dp_ctrl.is_return, sext_imm_p),
                                 use_if(dp_ctrl.is_return, reg_out_s));

        // setup control signals for pipeline register to next stage (memory access):
        load_store.is_load.in = dp_ctrl.is_load;
        load_store.is_store.in = dp_ctrl.is_store;
        load_store.addr.in = agen_result;
        load_store.value.in = reg_out_d;
        load_store.reg_d.in = compute.reg_d.out;


        /////////////////////////
        //
        // Load - Store:
        //
        /////////////////////////
        events.data_access_ok = memory_access(mem, load_store.addr.out, 
                                              load_store.is_valid.out && (load_store.is_load.out || load_store.is_store.out),
                                              load_store.is_store.out);
        val mem_out = memory_read(mem, load_store.is_load.out && load_store.is_valid.out);
        memory_write(mem, load_store.value.out, load_store.is_store.out && load_store.is_valid.out);


        //////////////////////////
        //
        // Pipeline control
        //
        //////////////////////////
        pipeline_control pipe_ctrl = control_pipeline(&fetch, &compute, &load_store, &events);

        // Pick a new instruction pointer. By default it's the one after the current one,
        // but if the compute stage requests an insn flow change AND runs in the current cycle,
        // we instead source the next ip from the ip computed by the datapath
        bool compute_overrides = pipe_ctrl.compute_runs && events.insn_flow_change_request && compute.is_valid.out;
        val selected_ip = or(use_if(compute_overrides, compute_next_ip),
                             use_if(!compute_overrides, next_ip));

        fetch.ip.in = selected_ip;

        bool stop_for_STOP = dp_ctrl.is_stop;
        bool stop_for_RET_NEGATIVE = dp_ctrl.is_return && pick_one(63, selected_ip);
        bool stop_for_RET_ZERO = dp_ctrl.is_return && is(0, selected_ip);
        stop = (stop_for_STOP || stop_for_RET_NEGATIVE || stop_for_RET_ZERO) 
          && compute.is_valid.out && pipe_ctrl.compute_runs;

        ++cycle_number;
        if (pipe_ctrl.compute_runs && compute.is_valid.out)
          ++insn_number;
        ///////////////////////////
        //
        // Pretty-print status
        //
        ///////////////////////////

#ifdef PRETTY_PRINTING
        printf("%6d", cycle_number);
        print_ctrl(pipe_ctrl.fetch_runs, pipe_ctrl.fetch_valid);
        printf("%6lx -> ", pc.val);
        if (events.insn_access_ok) {
            for (uint64_t n = 0; n < 10; ++n) {
                if (pc.val + n < next_ip.val) { printf("%02lx", inst_bytes[n].val); }
                else printf("  ");
            }
        }
        else printf("miss/busy           ");
        printf("    ");
        print_ctrl(pipe_ctrl.compute_runs, compute.is_valid.out);
        if (pipe_ctrl.compute_runs && compute.is_valid.out)
            print_decoded(compute.major_op.out, compute.minor_op.out);
        else
            printf("                         ");
        if (pipe_ctrl.compute_runs && compute.is_valid.out && dp_ctrl.reg_wr_enable) 
            printf("%16lx -> reg[%lx]", compute_result.val, compute.reg_d.out.val); 
        else printf("                          ");
        print_ctrl(pipe_ctrl.load_store_runs, load_store.is_valid.out);
        if (load_store.is_load.out && load_store.is_valid.out) {
            printf(" load (%lx) -> ", load_store.addr.out.val);
            if (events.data_access_ok)
                printf("%lx -> reg[%lx]", mem_out.val, load_store.reg_d.out.val);
            else printf("miss/busy");
        }
        else if (load_store.is_store.out && load_store.is_valid.out) {
            printf(" store %lx -> (%lx)", load_store.value.out.val, load_store.addr.out.val);
            if (!events.data_access_ok) printf("  miss/busy");
        }
        printf("\n");
#endif
        // write back load result to destination register
        reg_write(regs, load_store.reg_d.out, mem_out, load_store.is_load.out 
                  && load_store.is_valid.out && pipe_ctrl.load_store_runs);
        // write back compute result to destination register (goes after pretty printing, since they may signal an error)
        reg_write(regs, compute.reg_d.out, compute_result, dp_ctrl.reg_wr_enable 
                  && compute.is_valid.out && pipe_ctrl.compute_runs);
        memory_clk(mem);

        fetch_clk(&fetch);
        compute_clk(&compute);
        load_store_clk(&load_store);
    }
    memory_destroy(mem);
    regs_destroy(regs);

    printf("Done - %d instructions in %d cycles\n", insn_number, cycle_number);
}

CC = gcc
CFLAGS = -Wall -std=c11 -g -ggdb

all: sim

../src.zip: arithmetic.c arithmetic.h compute.c compute.h decode.c decode.h ip_reg.c ip_reg.h main.c Makefile memory.c memory.h pipe_ctrl.c pipe_ctrl.h print.c print.h registers.c registers.h support.c support.h test.c trace_read.c trace_read.h wires.c wires.h benchmark/quicksort.hex benchmark/heapsort.hex benchmark/mergesort.hex benchmark/run-performance.sh benchmark/README benchmark/c_reference_sources/alloc.c benchmark/c_reference_sources/heapsort.c benchmark/c_reference_sources/io.c benchmark/c_reference_sources/mergesort.c benchmark/c_reference_sources/quicksort.c
	cd .. && zip src.zip src/arithmetic.c src/arithmetic.h src/compute.c src/compute.h src/decode.c src/decode.h src/ip_reg.c src/ip_reg.h src/main.c src/Makefile src/memory.c src/memory.h src/pipe_ctrl.c src/pipe_ctrl.h src/print.c src/print.h src/registers.c src/registers.h src/support.c src/support.h src/test.c src/trace_read.c src/trace_read.h src/wires.c src/wires.h src/benchmark/quicksort.hex src/benchmark/heapsort.hex src/benchmark/mergesort.hex src/benchmark/run-performance.sh src/benchmark/README src/benchmark/c_reference_sources/alloc.c src/benchmark/c_reference_sources/heapsort.c src/benchmark/c_reference_sources/io.c src/benchmark/c_reference_sources/mergesort.c src/benchmark/c_reference_sources/quicksort.c


sim: *.c *.h
	$(CC) $(CFLAGS) *.c -o sim

clean:
	rm -rf *.o sim test_runs

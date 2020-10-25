/*
  Memory elements and IO devices

  Memory resizes dynamically to accomodate usage.
  IO Devices are located at addresses 0x1000000000 to 0x1FFFFFFF.
  Three IO devices are implemented:
  0x10000000 Input quadword from standard input
  0x10000001 Input pseudo-random quadword
  0x10000002 Output quadword to standard output
*/

#include "wires.h"

struct memory;
typedef struct memory *mem_p;

mem_p memory_create();
void memory_destroy(mem_p);
void memory_read_from_file(mem_p, const char* filename);

// set a tracefile for validation of memory writes and input/output
void memory_tracefile(mem_p mem, const char* filename);

// prepare to read or write from a byte-address. Captures the address in preparation
// of using memory_read() or memory_write(). Return true if later access (read or write)
// can be completed successfully.
bool memory_access(mem_p, val address, bool enable, bool is_write);

// Read quadword. We use little endian byte-addressing and support unaligned access
// If the address is to an input device, input will be performed instead of memory access
// Address must have been setup by memory_access() above.
val memory_read(mem_p, bool enable);

// Write quadword with new value at rising edge of clock.
// There are no internal forwarding from write to read in same clock period
// Little endian byte-addressing and unaligned access is supported
// If the address is to an output device, output will be performed instead of memory access
// Address must have been setup by memory_access() above.
// NOTE: Actual writing/output does not take place before calling memory_clk()
void memory_write(mem_p, val value, bool wr_enable);

// read 10 bytes unaligned, for instruction fetch. Return true if read was complete and succesfull
bool memory_read_into_buffer(mem_p, val address, val bytes[], bool enable);

// parse argument vector and load it into simulated argv area
void memory_load_argv(mem_p, int argc, char* argv[]);

// update memory with any pending changes
void memory_clk(mem_p);

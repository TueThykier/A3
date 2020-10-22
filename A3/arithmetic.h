/*
  Arithmetic stuff and simple gates
*/

#include "wires.h"

// mask out a value if control is false. Otherwise pass through.
val use_if(bool control, val value);

// bitwise and, or, xor and negate for bitvectors (generalized to 3,4,5 args for and/or)
val and(val a, val b);
val or(val a, val b);
val xor(val a, val b);
val and3(val a, val b, val c);
val or3(val a, val b, val c);
val and4(val a, val b, val c, val d);
val or4(val a, val b, val c, val d);
val and5(val a, val b, val c, val d, val e);
val or5(val a, val b, val c, val d, val e);
val neg(int num_bits, val); // only negate 'num_bits' of 'val'

// reduce a bit vector to a bool by and'ing or or'ing all elements
bool reduce_and(int num_bits, val); // only consider 'num_bits'
bool reduce_or(val);

// 64 bit addition
val add(val a, val b);

// detect specific value. Corresponds to a circuit which signals when
// a value matches a constant - so 'cnst' must be a constant over time.
bool is(uint64_t cnst, val a);
bool same(val a, val b);

// 64-bit adder that can also take a carry-in and deliver an unsigned overflow status.
typedef struct {
    bool cf;
    val result;
} generic_adder_result;

generic_adder_result generic_adder(val val_a, val val_b, bool carry_in);



/*
  Basic IO functions
*/

long read_long() {
  long read_addr = 0x10000000ULL;
  return * (volatile long *) read_addr;
}

long gen_random() {
  long read_addr = 0x10000001ULL;
  return * (volatile long *) read_addr;
}

void write_long(long value) {
  long write_addr = 0x10000002ULL;
  * (volatile long *) write_addr = value;
}

// We also support passing an argument vector of quads
long get_argc() {
  long read_addr = 0x20000000ULL;
  return * (volatile long *) read_addr;
}

long read_argv(long index) {
  long read_addr = 0x20000008ULL;
  return *(((volatile long*) read_addr) + index);
}

long* allocate(long num_entries); // forward decl
long* get_random_array(long num_entries) {
  long* p = allocate(num_entries);
  for (long i = 0; i < num_entries; ++i) {
    p[i] = gen_random();
  }
  return p;
}

long* read_array(long num_entries) {
  long* p = allocate(num_entries);
  for (long i = 0; i < num_entries; ++i) {
    p[i] = read_long();
  }
  return p;
}

void print_array(long num_elem, long array[]) {

  for (long i = 0; i < num_elem; ++i) {
    write_long(array[i]);
  }

}



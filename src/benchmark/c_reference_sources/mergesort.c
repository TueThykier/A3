#include "io.c"
#include "alloc.c"

inline void merge_run(long size_a, long size_b, long from[], long to[]) {
  long* p_a = from;
  long* p_a_limit = from + size_a;
  long* p_b = p_a_limit;
  long* p_b_limit = p_a_limit + size_b;
  long* target = to;
  long* target_limit = target + size_a + size_b;
  while (target < target_limit) {
    if (p_a < p_a_limit) {
      if (p_b < p_b_limit) {
        if (*p_a < *p_b) { *target = *p_a++; }
        else { *target = *p_b++; }
      }
      else { *target = *p_a++; }
    }
    else { *target = *p_b++; }
    ++target;
  }
}

void merge_runs(long total_size, long run_size, long from[], long to[]) {
  while (total_size) {
    long run_size_a = run_size;
    long run_size_b = run_size;
    if (total_size < run_size_a + run_size_b) 
      run_size_b = total_size - run_size_a;
    merge_run(run_size_a, run_size_b, from, to);
    from = from + run_size_a + run_size_b;
    to = to + run_size_a + run_size_b;
    total_size = total_size - run_size_a - run_size_b;
  }
}


void merge_sort(long num_elem, long array[]) {
  long* array_a = array;
  long* array_b = allocate(num_elem);
  long run_size = 1;
  while (run_size < num_elem) {
    merge_runs(num_elem, run_size, array_a, array_b);
    long* tmp = array_a;
    array_a = array_b;
    array_b = tmp;
    // array_a now holds result
    run_size <<= 1;
  }
  if (array_a != array) { // results in wrong array, must copy back
    for (long k = 0; k < num_elem; ++k)
      array[k] = array_a[k];
  }
}

long* run() {
  init_allocator();
  // Read it the program should print
  // 0: Silent mode
  // 1: Print sorted list
  // 2: Get input from stdin
  // 3: Test mode (print + input)
  long mode = read_long();
  long is_printing = mode & 1;
  long get_input = mode & 2;
  // Read number of elements in array
  long num_entries = read_long();
  long* p;
  // Run the algorithm
  if (get_input) {
    p = read_array(num_entries);
  }
  else {
    p = get_random_array(num_entries);
  }

  // Run the algorithm
  merge_sort(num_entries, p);

  if (is_printing) {
    print_array(num_entries, p);
  }
  return p; // <-- prevent optimization
}

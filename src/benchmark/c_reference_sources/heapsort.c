#include "io.c"
#include "alloc.c"

#define Swap(tab,x,y) { long tmp = tab[x]; tab[x] = tab[y]; tab[y] = tmp; }

#define Parent(i) (((i) - 1) >> 1)
#define LeftChild(i) (2*i + 1)
#define RightChild(i) (2*i + 2)

void sift_down(long start, long end, long array[]) {
  long root = start;
  while (LeftChild(root) <= end) {
    long child = LeftChild(root);
    long swap = root;
    if (array[swap] < array[child])
      swap = child;
    if (child + 1 <= end && array[swap] < array[child + 1])
      swap = child + 1;
    if (swap == root)
      return;
    else {
      Swap(array, root, swap);
      root = swap;
    }
  }
}

void heapify(long num_elem, long array[]) {
  long start = Parent(num_elem - 1);
  while (start >= 0) {
    sift_down(start, num_elem - 1, array);
    start--;
  }
}

void heap_sort(long num_elem, long array[]) {

  heapify(num_elem, array);

  long end = num_elem - 1;
  while (end > 0) {
    Swap(array, end, 0)
    end--;
    sift_down(0, end, array);
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
  long* p = get_random_array(num_entries);
  // Run the algorithm
  if (get_input) {
    p = read_array(num_entries);
  }
  else {
    p = get_random_array(num_entries);
  }

  heap_sort(num_entries, p);

  if (is_printing) {
    print_array(num_entries, p);
  }
  return p; // <-- prevent optimization
}

#!/bin/bash

# Set path so it matches your installation:
SIM=./sim


# algorithms to benchmark
algorithms="heapsort mergesort quicksort"

# Number of elements to be sorted
elements="25 50 100 200 400 800 1600 3200 6400 12800 25600"

for algo in ${algorithms}
do
  echo ""
  echo "Sorting with " $algo
  echo ""
  if [ ${algo} = "quicksort" ]; then
    entrypoint="338"
  elif [ ${algo} = "heapsort" ]; then
    entrypoint="39a"
  elif [ ${algo} = "mergesort" ]; then
    entrypoint="3d1"
  else 
    entrypoint="0"
  fi
  for elem in ${elements}
  do
    echo ""
    echo "Sorting with " ${algo} " - sorting" ${elem} "entries"
    echo "------------------"
#  ${SIM} ${1}.hex run $machine < runs/run-${elem}.input > ${datafile}
    printf "0\n${elem}\n" | ${SIM} ${algo}.hex ${entrypoint}
  done
done

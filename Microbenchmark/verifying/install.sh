#!/bin/bash
gcc -mmmx -msse2 -msse  -maes -O3  -mpreferred-stack-boundary=4  -march=native -o quick_verify  verify-bench.c
make
chmod +x quick_run.sh
sed -i -e 's/\r$//' quick_run.sh
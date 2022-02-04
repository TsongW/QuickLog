CC=gcc
CFLAGS= -mmmx -msse2 -msse  -maes -O3  -mpreferred-stack-boundary=4  -march=native

verify-bench: verify-bench.o 
     $(CC) -o verify verify-bench.o 

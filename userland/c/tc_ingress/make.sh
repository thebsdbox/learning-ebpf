#!/bin/bash
echo "Generating vmlinux.h"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../../headers/vmlinux.h

echo "Compiling eBPF code"
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86  -c ../../ebpf/tc_ingress/tc.c -o ./tc.o -v

echo "Stripping eBPF code"
llvm-strip -g tc.o

echo "Generating skeletion headers"
bpftool gen skeleton tc.o > tcSkeleton.h

echo "Compiling UX code"
cc -g -Wall -c ux.c -o ux.o

echo "Compiling final binary"
cc -g -Wall ./ux.o -lbpf -lelf -lz  -static -o lb -v
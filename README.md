This repository contains the source code of the prototypes for the secure logging schemes QuickLog and QuickLog2 in the paper:
"Faster Yet Safer: Logging System Via Fixed-Key Blockcipher".

# Overview
QuickLog follows the blueprint in the work of Bellare and Yee (CT-RSA 2003) but uses a one-time MAC instead of a standard MAC.
The key idea for performance improvement is to build both the one-time MAC and the key-derivation function on top of a fixed-key blockcipher.
We extend QuickLog to a scheme QuickLog2 of aggregate authentication. 
The signing and updating algorithms of QuickLog2 remain the same as those of QuickLog, and its Merge algorithm is built on top of the xor trick from "Aggregate message authentication codes" of Katz and Lindell .

# Setup
We ran our evaluation using the following setup:

- CentOS 7 (Linux version 3.10.0-1160.49.1.el7) with Linux Audit version 2.8.5-4.el7
(Please make sure the version of the Linux kernel is 3.10)


# Instructions for evaluating signing cost
To measure the application-independent running time of the
signing cost of QuickLog/QuickLog2, you need to create a kernel module as follows:

- Run ` sudo yum install "kernel-devel-uname-r == $(uname -r)" `
- Go to the `signing` directory and run `make` to compile.
- Run  `sudo dmesg --clear`
- Load `quickmod` via `sudo insmod quickmod.ko len=[message length]` 
- Run`dmesg` command to check results.
- Unload the kernel module using `sudo rmmod quickmod` when you are done.

# Instructions for evaluating verification cost
Verification can be run from the user space. To measure the verification cost,

- Go to the `verifying` directory and run `make` to compile.
- Run `./verify [data length]`.
- Run `make clean` when you are done.

# Install 

- Download the kernel source (3.10.0-1160.49.1.el7)

- Follow these steps to patch the kernel and install： https://wiki.centos.org/HowTos/Custom_Kernel 
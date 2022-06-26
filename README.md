This repository contains the source code of the secure logging schemes QuickLog and QuickLog2 in the paper:
"Faster Yet Safer: Logging System Via Fixed-Key Blockcipher".
We also include the code of the competitor KennyLoggings that we used for performance comparison.



# Run-time environment
We ran our evaluation in CentOS 7 (Linux version 3.10.0-1160.49.1.el7) with Linux Audit version 2.8.5-4.el7. 
We also tested our code on Ubuntu 18 (Linux 5.4.0-120-generic) to ensure that our code works with other Linux distributions. The code requires root access.

# How to evaluate signing cost
To measure the application-independent running time of the signing cost of QuickLog, QuickLog2, and KennyLoggings:

- Go to the `signing` directory, select the folder that corresponds to your kernel, and run `./install.sh` to compile.
- Run  `./quick_run.sh ` to benchmark.

# How to evaluate verification cost
To measure the verification cost,

- Go to the `verifying` directory and run `./install.sh` to compile.
- Run `./verify_run.sh `to benchmark.


# Install 

- Download the kernel source (3.10.0-1160.49.1.el7)

- Follow these steps to patch the kernel and install： https://wiki.centos.org/HowTos/Custom_Kernel 
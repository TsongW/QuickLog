This repository contains the source code of the prototypes for secure logging scheme QuickLog in the paper:
"Faster Yet Safer: Logging System Via Fixed-Key Blockcipher".



# Overview
QuickLog follows the blueprint in the work of Bellare and Yee (CT-RSA 2003) but uses a one-time MAC instead of a standard MAC. 
The key idea for performance improvement is to build both the one-time MAC and the key-derivation function on top of a fixed-key blockcipher.

# Setup
We ran our evaluation using the following setup:

- CentOS 7 (Linux version 3.10.0-1160.49.1.el7) with Linux Audit version 2.8.5-4.el7 

- You can download from here:
  http://vault.centos.org/7.9.2009/updates/Source/SPackages/kernel-3.10.0-1160.49.1.el7.src.rpm


# Test Signing Instructions
To test QuickLog signing in kernel module:

- Enter the `signing` directory and run `make` to compile. 
- Load `quickmod` using `sudo insmod quickmod.ko` command.(You may use `sudo dmesg --clear` before load, making the output clear).
- Run`dmesg` command to check results. 
- When you are done, unload the kernel module using `sudo rmmod quickmod`.


# Test Verifying Instructions
To test QuickLog verifying in user space:

- Enter the `verifying` directory and run `make` to compile. 
- Using `./verify` to run.
- When you are done, using `make clean` to remove.
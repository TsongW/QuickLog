This repository contains the source code of the prototypes of the secure logging scheme QuickLog the paper:
"Faster Yet Safer: Logging System Via Fixed-Key Blockcipher".



# Overview
QuickLog follows the blueprint in the work of Bellare and Yee but uses a one-time MAC instead of a standard MAC. 
The key idea for performance improvement here is to build both signning function and key-generating function on top of a fixed-key blockcipher. 

# Tested Setup
We ran our evaluation using the following setup:

- CentOS 7 (Linux version 3.10.0-1160)
- Linux Audit installed 

# Instructions

## Kernel Module
To run QuickLog with kernel module:

- Enter the `kernel-module` directory and run `make`.
- (optional) Clear the message buffer of the kernel using `sudo dmesg --clear`.
- Load `quickmod` using `sudo insmod quickmod.ko`.
- You can see what the kernel module did using `dmesg`.
- When you are done, unload the kernel module using `sudo rmmod quickmod`.

## Kernel Patches
To apply the kernel patches, build and run the patched kernel, we recommend the following steps:

- Download Linux kernel 3.10.0-1160.49.1.el7 from here:
  http://vault.centos.org/7.9.2009/updates/Source/SPackages/kernel-3.10.0-1160.49.1.el7.src.rpm

- Patch the extracted kernel using our provided kernel patch `quick.patch`.

- Compile and install the patched kernel

- Reboot your machine into the custom kernel
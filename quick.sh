#!/bin/bash

cd kernel-module

make clean && make

sudo dmesg --clear
sudo insmod quickmod.ko
dmesg
sudo rmmod quickmod


sudo dmesg --clear
sudo insmod quickmod.ko
dmesg
sudo rmmod quickmod

sudo dmesg --clear
sudo insmod quickmod.ko
dmesg
sudo rmmod quickmod

sudo dmesg --clear
sudo insmod quickmod.ko
dmesg
sudo rmmod quickmod


sudo dmesg --clear
sudo insmod quickmod.ko
dmesg
sudo rmmod quickmod

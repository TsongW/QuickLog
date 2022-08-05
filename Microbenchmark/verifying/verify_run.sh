#!/bin/bash

echo "_______Starting: log size = 64B______"
sudo dmesg --clear
sudo insmod cryptomod.ko len=64
dmesg
sudo rmmod cryptomod
sleep 2
./quick_verify 64
sleep 2

echo "_______Starting: log size = 128B______"
sudo dmesg --clear
sudo insmod cryptomod.ko  len=128
dmesg
sudo rmmod cryptomod
sleep 2
./quick_verify 128
sleep 2

echo "_______Starting: log size = 256B______"
sudo dmesg --clear
sudo insmod cryptomod.ko  
dmesg
sudo rmmod cryptomod
sleep 2
./quick_verify 
sleep 2
echo "_______Starting: log size = 320B______"
sudo dmesg --clear
sudo insmod cryptomod.ko  len=320
dmesg
sudo rmmod cryptomod
sleep 2
./quick_verify 320
sleep 2
echo "_______Starting: log size = 384B______"
sudo dmesg --clear
sudo insmod cryptomod.ko  len=384
dmesg
sudo rmmod cryptomod
sleep 2
./quick_verify 384

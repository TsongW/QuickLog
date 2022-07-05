#!/bin/bash

sudo apt install auditd
make
chmod +x quick_run.sh
sed -i -e 's/\r$//' quick_run.sh

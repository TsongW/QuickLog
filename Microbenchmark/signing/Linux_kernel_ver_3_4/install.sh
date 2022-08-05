#!/bin/bash
sudo yum install audit audit-libs
sudo yum install "kernel-devel-uname-r == $(uname -r)"
make
chmod +x quick_run.sh
sed -i -e 's/\r$//' quick_run.sh
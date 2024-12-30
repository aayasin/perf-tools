#!/bin/bash
# Author: Ahmad Yasin, Dec. 2024
wget https://www.python.org/ftp/python/3.12.0/Python-3.12.0.tgz
tar -xf Python-3.12.0.tgz
export CFLAGS='-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer'
cd Python-3.12.0
./configure --enable-optimizations
make -j `nproc`
./python --version
./python -m sysconfig | grep frame

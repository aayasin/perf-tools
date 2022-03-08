#!/bin/sh
set -xe
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
# if previous command fails, try this alternative :
# wget https://mirrors.edge.kernel.org/pub/linux/kernel/tools/perf/v5.14.0/perf-5.14.0.tar.xz && tar -xvf ./perf-5.14.0.tar.xz
cd ./linux/tools/perf/
sudo apt-get install -y flex
sudo apt-get install -y bison
sudo apt-get install libslang2-dev
#sudo apt-get install libelf
sudo apt-get install make
#warning: next line was tested on Ubuntu
sudo apt-get install -y libbfd-dev libdwarf-dev libelf-dev
make clean
make
ls -l $PWD/perf
cp perf ../../../../
set +x

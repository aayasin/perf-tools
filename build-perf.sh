#!/bin/sh
CLONE=${CLONE:-2}
PERFV=${PERFV:-5.15.0}
LINUXV=${PERFV:-5.19.3}
OBJDUMP=${OBJDUMP:-0}

perfdir=linux/tools/perf
set -xe
if [ $CLONE -eq 1 ]; then
  git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
elif [ $CLONE -eq 2 ]; then
  wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-$LINUXV.tar.xz
  tar -vxf linux-$LINUXV.tar.xz
  perfdir=linux-$LINUXV/tools/perf
else
  # if previous commands fail, try this alternative :
  wget https://mirrors.edge.kernel.org/pub/linux/kernel/tools/perf/v$PERFV/perf-$PERFV.tar.xz
  tar -xvf ./perf-$PERFV.tar.xz
  perfdir=perf-$PERFV/tools/perf
fi

cd $perfdir
sudo apt-get install -y flex
sudo apt-get install -y bison
sudo apt-get install libslang2-dev
sudo apt-get install libiberty-dev libzstd-dev #demangle
#sudo apt-get install libelf
sudo apt-get install make
#warning: next line was tested only on Ubuntu
sudo apt-get install -y libbfd-dev libdwarf-dev libelf-dev libdw-dev libunwind-dev
make clean
#make PYTHON=false PYTHON_CONFIG=false
make
ls -l $PWD/perf
cp perf ../../../../
cd -

if [ $OBJDUMP -eq 1 ]; then
  sudo apt-get install -y libgmp-dev
  git clone http://sourceware.org/git/binutils-gdb.git
  cd binutils-gdb/
  ./configure
  make
  cd ..
  ls -l ./binutils-gdb/binutils/objdump
fi

set +x

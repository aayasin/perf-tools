#!/bin/sh
CLONE=${CLONE:-3}
PERFV=${PERFV:-6.12.0}	    # last good: 5.15.111
LINUXK=${LINUXK:-5}
LINUXV=${LINUXV:-5.19.17}   # upgrade to 6.7 (may need to set NO_LIBTRACE_EVENT=1
                            # or to <= 6.2.16 for JIT support, not 6.4!.
                            # besides: https://github.com/andikleen/pmu-tools/issues/457
OBJDUMP=${OBJDUMP:-0}

perfdir=linux/tools/perf
if [ $CLONE -eq 2 ]; then perfdir=linux-$LINUXV/tools/perf; fi
if [ $CLONE -eq 3 ]; then perfdir=perf-$PERFV/tools/perf; fi
set -xe
if [ ! -d "$perfdir" ]; then
  if [ $CLONE -eq 1 ]; then
    git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
  elif [ $CLONE -eq 2 ]; then
    wget https://cdn.kernel.org/pub/linux/kernel/v$LINUXK.x/linux-$LINUXV.tar.xz
    tar -xf linux-$LINUXV.tar.xz
  else #3
    # if previous commands fail, try this alternative :
    wget https://mirrors.edge.kernel.org/pub/linux/kernel/tools/perf/v$PERFV/perf-$PERFV.tar.xz
    tar -xf ./perf-$PERFV.tar.xz
  fi
fi
cd $perfdir
sudo apt-get install -y flex
sudo apt-get install -y bison
sudo apt-get install libslang2-dev
sudo apt-get install libiberty-dev libzstd-dev #demangle
#sudo apt-get install libelf
sudo apt-get install make
#warning: next line was tested only on Ubuntu
sudo apt-get install -y libtraceevent-dev libbfd-dev libdwarf-dev libelf-dev libdw-dev libunwind-dev
make clean
#make PYTHON=false PYTHON_CONFIG=false
make NO_JEVENTS=1 # a perf tool overhead bug in Intel event names handling
ls -l $PWD/perf
cd -
ln -sf $PWD/$perfdir/perf ../perf

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

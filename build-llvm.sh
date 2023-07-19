#!/bin/sh
# VER 1.5
set -e

LLVMVER=${LLVMVER}
OVERRIDE=${OVERRIDE:-false}

while getopts "o" opt; do
  case ${opt} in
    o)
      OVERRIDE=true
      ;;
    \?)
      exit 1
      ;;
  esac
done

if [ "$OVERRIDE" = "false" ] && [ -x "/usr/local/bin/llvm-mca" ]; then
    cur_ver=$(/usr/local/bin/llvm-mca --version | grep version | awk '{print $3}')
    if [ -z "$LLVMVER" ] || [ "$cur_ver" = "$LLVMVER" ]; then
        echo "\033[1;32mLLVM ALREADY INSTALLED!\033[0m"
	    exit
	fi
fi

red_cmd() {
    "$@" | cut -d: -f2- | sed 's/^[ \t]*//' | tr '[:upper:]' '[:lower:]'
}

if [ -f /etc/os-release ]; then
    DIST=$(grep '^ID=' /etc/os-release | cut -d= -f2- | sed 's/"//g')
else
    DIST=$(red_cmd lsb_release -i | sed 's/"//g')
fi

case $DIST in
ubuntu)
    cmd=gnu-ubuntu-18.04
    VER=16.0.0
    ;;
suse)
    cmd=sles12.4
    VER=14.0.0
    ;;
rhel)
    cmd=gnu-rhel-8.4
    VER=15.0.0
    ;;
*)
    echo "\033[1;31mLLVM DOESN'T SUPPORT YOUR LINUX DISTRIBUTION, BUILD FAILED!\033[0m"
    exit 1
esac

if [ -z "$LLVMVER" ]; then
    LLVMVER=$VER
fi
LLVM=clang+llvm-$LLVMVER-x86_64-linux-$cmd

if ! wget -q --spider https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVMVER/$LLVM.tar.xz; then
    echo "\033[0;36mThe desired LLVM version does not exist or it doesn't support your linux distribution.
You can try one of the following:
    1. Run again without specifying a version, the default version for your distribution will be installed.
    2. Try another version, check https://releases.llvm.org/download.html for all available versions.\033[0m"
    exit 1
fi

LOG=llvm_build.log
red_log() {
    "$@" >> $LOG 2>&1 | tee /dev/stderr
}

echo "Installing, please wait ..."
echo > $LOG
wget -q https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVMVER/$LLVM.tar.xz
red_log tar -xvf $LLVM.tar.xz
sudo install -m 755 $LLVM/bin/llvm-mca /usr/local/bin
echo "Done! :)"

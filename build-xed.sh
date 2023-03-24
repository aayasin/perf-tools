#!/bin/sh
set -x
git clone https://github.com/intelxed/mbuild.git mbuild
git clone https://github.com/intelxed/xed
cd xed
# sudo apt install build-essential --fix-missing
./mfile.py --share 2>&1 | tee mfile.log | grep VERSION
./mfile.py examples >> mfile.log 2>&1
sudo ./mfile.py --prefix=/usr/local install >> mfile.log 2>&1
sudo ldconfig
sudo install -m 755 obj/wkit/examples/obj/xed /usr/local/bin
set +x

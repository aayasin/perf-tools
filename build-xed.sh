#!/bin/sh
set -x
git clone https://github.com/intelxed/mbuild.git mbuild
git clone https://github.com/intelxed/xed
cd xed
./mfile.py --share
./mfile.py examples
sudo ./mfile.py --prefix=/usr/local install
sudo ldconfig
sudo cp obj/wkit/examples/obj/xed /usr/local/bin
set +x

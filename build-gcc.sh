#!/bin/sh
set -x
git clone  https://github.com/gcc-mirror/gcc GCC-14
cd GCC-14
./contrib/download_prerequisites
cd ..
mkdir gcc_install
cd gcc_install
$PWD/../GCC-14/configure --prefix=$PWD/GCC-14 --enable-languages=c,c++,fortran,go  --disable-multilib 
make -j$(nproc) 
make install -j$(nproc) 
echo ""
echo "Please use the below bash commandline for-loop to move your old toolchain softlinks to *.perftools and make this new version of gcc and main toolchain"
echo "for i in gcc gcc-ar gcc-ranlib gcc-nm cpp c++ g++;do mv /usr/bin/$i /usr/bin/$i"\.perftools"; ln -sf $PWD/GCC-14/bin/$i /usr/bin/ ;done"
echo ""
echo "Please use the below bash commandline for-loop to revert from this version of gcc to the original"
echo "for i in gcc gcc-ar gcc-ranlib gcc-nm cpp c++ g++;do mv /usr/bin/$i"\.perftools" /usr/bin/$i;done"
echo ""
set +x 

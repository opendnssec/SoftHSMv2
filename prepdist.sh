#!/bin/sh

PREFIX=/tmp/softhsm2-release
export LD_LIBRARY_PATH=/usr/local/lib

if [ ! -f autogen.sh -a ! -f configure ]; then
        echo "Unable to continue, no autogen.sh or configure"
        exit 1
fi

if [ -f autogen.sh ]; then 
        sh autogen.sh 
fi &&
mkdir -p build &&
cd build &&
../configure --prefix=${PREFIX} \
	--with-crypto-backend=botan \
	--with-botan=/usr/local \
	$@

#!/bin/bash

if [[ $EUID -ne 0 ]]
	then echo "This script must run as root"
	exit 1
fi

set -e

rm -rf build

mkdir build && cd build
cmake ..
make -j6
make install

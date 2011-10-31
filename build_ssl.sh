#!/bin/bash

cd ~/Dropbox/snort/src/dynamic-preprocessors
echo -n "Building dynamic-preprocessors directory, currently in directory "
pwd

make
cd ssl
make
sudo make install

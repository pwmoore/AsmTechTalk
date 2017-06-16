#!/usr/bin/env bash
sudo apt update
sudo apt install -y cmake
git submodule update --init --recursive
cd capstone
./make.sh
sudo make install
cd ..
cd keystone
mkdir build
cd build
../make-share.sh
sudo make install
cd ../..
cd unicorn
./make.sh
sudo make install 
cd ..


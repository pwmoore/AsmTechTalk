#!/usr/bin/env bash
if [ -e ./.deps ];
then
	exit 0;
fi

sudo apt update
sudo apt install -y build-essential nasm cmake
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
sudo ldconfig
touch .deps

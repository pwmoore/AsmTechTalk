# AsmTechTalk

This repository contains sample code for a tech talk given at Hell 'n' Blazes for HackSpaceCoast.

# Environment

The code here should be fairly generic and work on any Linux based OS. I used a 32-bit Ubuntu 16.04.2 VM. 64-bit should be fine with gcc-multilib
and 32-bit libraries installed.

## VM Software

[VMWare](https://www.vmware.com) or [Virtualbox](https://www.virtualbox.org) should be fine. Virtualbox can be downloaded for free [here](https://www.virtualbox.org/wiki/Downloads). 

## VM Setup

Download the Ubuntu 16.04.2 32-bit ISO [here](http://releases.ubuntu.com/16.04/ubuntu-16.04.2-desktop-i386.iso). A guide for installing Ubuntu with Virtualbox on Windows can be found [here](https://www.lifewire.com/run-ubuntu-within-windows-virtualbox-2202098). Instructions should work similarly on Virtualbox for macOS. 

Once the VM is installed, log in and perform the following command: 

```
sudo apt update
sudo apt upgrade
sudo apt install git
git clone https://www.github.com/pwmoore/AsmTechTalk.git
```

## Installing Dependencies
Once the clone is complete, do the following:

```
cd AsmTechTalk
make
```

This will pull down all the dependencies, build the required libraries, install them, and build the sample code. 


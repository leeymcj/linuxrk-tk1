#!/bin/sh
# a) Put your system into "reset recovery mode" by holding down the RECOVERY
#      button and press RESET button once on the main board.
#   b) Ensure your Linux host system is connected to the target device
#      through the USB cable for flashing as below.
# $ lsusb
#   Bus 006 Device 010: ID 0955:7140 NVidia Corp.

#download Nvidia tool and sample file system
wget https://developer.nvidia.com/sites/default/files/akamai/mobile/files/L4T/Tegra124_Linux_R19.3.0_armhf.tbz2
wget https://developer.nvidia.com/sites/default/files/akamai/mobile/files/L4T/Tegra_Linux_Sample-Root-Filesystem_R19.3.0_armhf.tbz2
sudo tar xpf Tegra124_Linux_R19.3.0_armhf.tbz2
cd Linux_for_Tegra/rootfs/
sudo tar xpf ../../Tegra_Linux_Sample-Root-Filesystem_R19.3.0_armhf.tbz2
cd ../
sudo ./apply_binaries.sh

#flash the rootfs onto eMMC
sudo ./flash.sh -S 8GiB jetson-tk1  mmcblk0p1 #this tkae about 30 minutes

#reset board to boot from eMMC

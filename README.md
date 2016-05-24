# linuxrk-tk1

# TK1 flashing guide 

Requirement: HostLinux must be x86, Jetson ehternet connected, USB Micro-B cable


# 0. only if your TK1 is not R19.3 (3.10.24 kernel)
0.[on HostLinux] flash TK1 to R19.3 by running flash_R19.3.sh with root permission

 a) Put your system into "reset recovery mode" by holding down the RECOVERY button and press RESET button once on the main board.
      
   b) Ensure your Linux host system is connected to the target device through the USB cable for flashing as below.
 
 $ lsusb
 
   Bus 006 Device 010: ID 0955:7140 NVidia Corp.

https://github.com/leeymcj/linuxrk-tk1/blob/master/flash_R19.3.sh

sudo ./flash_R19.3.sh

//It will download and extract Linux for Tegra R19.3, referred as $(Linux_for_Tegra)

//reset board

#NOW if your TK1 is R19.3 (3.10.24 kernel)
1. [on TK1] Compile the kernel and module

git clone https://github.com/leeymcj/linuxrk-tk1.git

cd linuxrk-tk1

make -j4

make modules

make modules_install

cd mcrkmod

make //it will generate rk.ko

//check modules installed

ls /lib/modules

//3.10.24-rk is installed

//copy kernel image to host machine to flash
scp arch/arm/boot/zImage $(host_machine):$(Linux_for_Tegra)/kernel/

2. [on HostLinux] flash kernel $(pwd)=Linux_for_Tegra

// Put your system into "reset recovery mode" by holding down the RECOVERY button and press RESET button once on the main board.

sudo ./flash.sh -k 6 jetson-tk1 mmcblk0p1 

//reset


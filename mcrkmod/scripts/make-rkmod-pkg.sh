#!/bin/bash
#
# DO NOT EDIT THIS FILE
# It is automatically generated by ./make-kernel-pkg.sh
#
REVISION=1.0
APPEND=
KERNEL_VER=3.0.35-rk

cd ../
make
rm -rf linux-rk-mod-3.0.35-rk_1.0_`date +%b%d-%Y`
mkdir linux-rk-mod-3.0.35-rk_1.0_`date +%b%d-%Y`
cp rk.ko linux-rk-mod-3.0.35-rk_1.0_`date +%b%d-%Y`/rk_partitioned.ko
make global
cp rk.ko linux-rk-mod-3.0.35-rk_1.0_`date +%b%d-%Y`/rk_global.ko
cd linux-rk-mod-3.0.35-rk_1.0_`date +%b%d-%Y`
ln -s rk_partitioned.ko rk.ko

update_kernel_path() {
	if [ -n "$1" ]; then
		TGT=/$1
	fi
	mkdir mcrkmod$TGT
	cp ..$TGT/*.sh mcrkmod$TGT
	cp ..$TGT/*.c mcrkmod$TGT
	sed "s/$2 =.*/$2 = \/usr\/src\/linux-headers-$KERNEL_VER$APPEND/" ..$TGT/Makefile > mcrkmod$TGT/Makefile
}

update_kernel_path "" KDIR
update_kernel_path utils KERNEL_DIR
update_kernel_path utils/mem-reserve KERNEL_DIR
#update_kernel_path utils/virt KERNEL_DIR

mkdir mcrkmod/tests

update_kernel_path tests/multicore KERNEL_DIR
update_kernel_path tests/rk_mutex KERNEL_DIR
#update_kernel_path tests/vmpcp_intervm KERNEL_DIR
#update_kernel_path tests/cpursv KERNEL_DIR

cd ../
tar cvfz linux-rk-mod-3.0.35-rk_1.0_`date +%b%d-%Y`.tgz linux-rk-mod-3.0.35-rk_1.0_`date +%b%d-%Y`


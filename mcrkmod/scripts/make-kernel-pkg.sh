#!/bin/bash

CMD=$1

source rk-version

#APPEND=-imx
KERNEL_VER=$BASE_KERNEL_VERSION-rk
REVISION=$RK_VERSION


#######################################################################
##
## Generate RK module packaging script
##
#######################################################################

MKMOD_SH=make-rkmod-pkg.sh
MODDIR=linux-rk-mod-$KERNEL_VER$APPEND"_"$REVISION"_\`date +%b%d-%Y\`"
rm -f $MKMOD_SH

cat >> $MKMOD_SH << EOF
#!/bin/bash
#
# DO NOT EDIT THIS FILE
# It is automatically generated by $0
#
REVISION=$REVISION
APPEND=$APPEND
KERNEL_VER=$KERNEL_VER

cd ../
make
rm -rf $MODDIR
mkdir $MODDIR
cp rk.ko $MODDIR/rk_partitioned.ko
make global
cp rk.ko $MODDIR/rk_global.ko
cd $MODDIR
ln -s rk_partitioned.ko rk.ko

update_kernel_path() {
	if [ -n "\$1" ]; then
		TGT=/\$1
	fi
	mkdir mcrkmod\$TGT
	cp ..\$TGT/*.sh mcrkmod\$TGT
	cp ..\$TGT/*.c mcrkmod\$TGT
	sed "s/\$2 =.*/\$2 = \/usr\/src\/linux-headers-\$KERNEL_VER\$APPEND/" ..\$TGT/Makefile > mcrkmod\$TGT/Makefile
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
tar cvfz $MODDIR.tgz $MODDIR

EOF

chmod 755 $MKMOD_SH
echo $MKMOD_SH generated

#######################################################################
##
## Compile kernel package & Generate KPKG install script
##
#######################################################################

CONCURRENCY_LEVEL=8

case "$CMD" in
	all)
		cd ../../
		#fakeroot make-kpkg --initrd --append-to-version=$APPEND --revision=$REVISION kernel-image kernel-headers
		DEB_HOST_ARCH=armhf fakeroot make-kpkg --arch arm --cross-compile arm-linux-gnueabihf- --initrd --revision=$REVISION kernel-image kernel-headers
	;;
	headers)
		cd ../../
		DEB_HOST_ARCH=armhf fakeroot make-kpkg --arch arm --cross-compile arm-linux-gnueabihf- --revision=$REVISION kernel-headers
	;;
	*)
		echo "Available commands:"
		echo "  $0 all: make kernel-image and kernel-header packages"
		echo "  $0 headers: make kernel-header package only"
		exit 1
esac

cd ../

<<COMMENT1
TARGET=amd64
INSTALL_SH=install-linux-$KERNEL_VER$APPEND"_"$REVISION"_"$TARGET.sh
rm -f $INSTALL_SH
echo "#!/bin/sh" >> $INSTALL_SH
echo "sudo dpkg -i --force-all linux-headers-"$KERNEL_VER$APPEND"_"$REVISION"_"$TARGET".deb" >> $INSTALL_SH
echo "sudo dpkg -i --force-all linux-image-"$KERNEL_VER$APPEND"_"$REVISION"_"$TARGET".deb" >> $INSTALL_SH
echo "sudo ln -s /usr/src/linux-headers-"$KERNEL_VER$APPEND" /lib/modules/"$KERNEL_VER$APPEND"/build" >> $INSTALL_SH
echo "sudo mkinitramfs "$KERNEL_VER$APPEND" -o /boot/initrd.img-"$KERNEL_VER$APPEND >> $INSTALL_SH
echo "sudo update-grub" >> $INSTALL_SH
COMMENT1


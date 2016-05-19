#!/bin/bash
# Linux/RK code backup script for iMX6

cd ../../
rm -rf RK-Backup-`date +%b-%d-%Y`
mkdir RK-Backup-`date +%b-%d-%Y`
cd RK-Backup-`date +%b-%d-%Y`

# Copy RK module 
cp ../mcrkmod . -r

# Copy Makefile and configs
cp ../Makefile .
cp ../config-* .

# Make directories
mkdir arch
cd arch
mkdir arm 
cd arm
mkdir include
mkdir kernel
cd include
mkdir asm
cd ../../../
mkdir kernel
mkdir mm
mkdir include
cd include
mkdir linux
cd ..
mkdir scripts

# Copy kernel files
cp ../scripts/setlocalversion scripts/

cp ../include/rk include/ -r
cp ../include/linux/sched.h include/linux/
cp ../include/linux/mm_types.h include/linux/
cp ../include/linux/page-flags.h include/linux/
cp ../include/linux/rmap.h include/linux/

cp ../mm/rmap.c mm/
cp ../mm/vmscan.c mm/
cp ../mm/page_alloc.c mm/
cp ../mm/memory.c mm/
cp ../mm/migrate.c mm/

cp ../kernel/Makefile kernel/
cp ../kernel/fork.c kernel/
cp ../kernel/exit.c kernel/
cp ../kernel/rk.c kernel/
cp ../kernel/sched.c kernel/

cp ../arch/Kconfig arch/
cp ../arch/arm/include/asm/unistd.h arch/arm/include/asm/
cp ../arch/arm/kernel/armksyms.c arch/arm/kernel/
cp ../arch/arm/kernel/calls.S arch/arm/kernel/



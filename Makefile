obj-m += anti_danger.o

# 交叉编译环境配置 (根据你的编译环境修改)
KDIR ?= /path/to/android15-6.6-common/out
CC = clang
LD = ld.lld

all:
	make -C $(KDIR) M=$(PWD) ARCH=arm64 LLVM=1 modules

clean:
	make -C $(KDIR) M=$(PWD) ARCH=arm64 LLVM=1 clean
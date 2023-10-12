OUTPUT := .output
CLANG ?= clang
CC ?= gcc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../../../tools/bpftool)
LIBBPF_SRC := $(abspath ../../../libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' 		\
			 | sed 's/aarch64/arm64/' 	\
			 | sed 's/ppc64le/powerpc')
			
VMLINUX := ../../../vmlinux/$(ARCH)/vmlinux.h
WORKDIR := ../../../ebpf

INCLUDES := -I./ -I$(OUTPUT) -I../../../libbpf/include/uapi -I../../../ebpf/ -I$(dir $(VMLINUX)) -I$(WORKDIR)/container -I/usr/src/linux-headers-6.2.0-34-generic/tools/bpf/resolve_btfids/libbpf/include/
CFLAGS := -g -Wall 

# Custom configure(need manual mod)
TESTCASE := container
TESTS = getcidtest

.PHONY : all
all: $(TESTS)

.PHONY:clean
clean:
	$(call msg,CLEAN)
	rm -rf $(OUTPUT) $(TESTS) $(TESTS).o

$(TESTS): $(TESTS).c $(wildcard %.h)
	$(call msg,CC,$@)
	$(CC) $(CFLAGS) $(INCLUDES) $(filter $(TESTS).c, $^) $(WORKDIR)/$(TESTCASE)/$(TESTCASE).c -o $@
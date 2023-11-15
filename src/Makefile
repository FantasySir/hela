# Copyright (c) 2023 Broin All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

OUTPUT := .output

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../tools/bpftool)
LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)

VMLINUX := ../../vmlinux/x86/vmlinux.h
INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(dir $(VMLINUX))

# Sub directions
EBPF_DIRS := $(shell find $(abspath ../ebpf/) -mindepth 1 -maxdepth 1 -type d)

# Use customed libbpf api & uapi
CFLAGS := -g -Wall -Wno-unused-function -fsanitize=address

# List of .c files that should be compiled for the hela binary
HELA_SRCS := $(wildcard *.c)
HELA_OBJS := $(patsubst %.c, $(OUTPUT)/%.o, $(HELA_SRCS))

ifeq ($(V), 1)
	Q = 
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))"
	MAKEFLAGS += --no-print-directory
endif



.PHONY:all 
all: $(LIBBPF_OBJ) $(EBPF_DIRS) copy hela

.PHONY:clean
clean:
	$(foreach N, $(EBPF_DIRS), make clean -C $(N);)
	$(Q)rm -rf $(OUTPUT) hela 

.PHONY: copy
copy:
	@find ../ebpf -path '*/.output/*.bpf.o' -exec cp {} $(OUTPUT) \;
	@find ../ebpf -path '*/.output/*.h' -exec cp {} $(OUTPUT) \;

# Make ebpf/* prog
.PHONY: subdirs $(EBPF_DIRS)
subdirs: $(EBPF_DIRS)
$(EBPF_DIRS):
	@+make -C $@




$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build bpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1	\
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)	\
		    INCLUDEDIR= LIBDIR= UAPIDIR=		\
		    install

# # Generate bpf skeletons
# $(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
# 	$(call msg,GEN-SKEL,$@)
# 	$(Q)$(BPFTOOL) gen skeleton $< > $@

# # Compile user-space code
# $(patsubst %, $(OUTPUT)/%.o, $(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c, $^) -o $@

# Build binary
hela: $(HELA_OBJS) $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# Keep intermediate (.skel.h, .bpf.o ...) targets
.SECONDARY:
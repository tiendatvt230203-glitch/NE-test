CC        = gcc
CLANG     = clang
CFLAGS    = -D_GNU_SOURCE -Iinc -Wall -O2
LDFLAGS   = -lbpf -lxdp -pthread

# Môi trường header libbpf 1.x nhưng .so cũ (thiếu bpf_xdp_attach): make CFLAGS+=' -DNE_PLAIN_BPF_XDP_LEGACY'

# Default: no -g so the .o has no .BTF — avoids noisy "bpf_create_map_xattr ... Retrying without BTF"
# on kernels/libbpf where map+BTF create fails first then succeeds without BTF.
# For BTF/line info: make EXTRA_BPF_CFLAGS=-g
BPF_CFLAGS     = -O2 -target bpf $(EXTRA_BPF_CFLAGS)
KERNEL_HEADERS = /usr/include

BIN_DIR = bin
TARGET  = $(BIN_DIR)/ne-plain

SRC     = main.c src/config_file.c src/forwarder.c src/interface.c src/flow_table.c
OBJ     = $(SRC:.c=.o)

BPF_SRC = bpf/xdp_redirect.c bpf/xdp_wan_redirect.c
BPF_OBJ = bpf/xdp_redirect.o bpf/xdp_wan_redirect.o

.PHONY: all clean dirs

all: dirs $(BPF_OBJ) $(TARGET)

dirs:
	@mkdir -p $(BIN_DIR)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -c $< -o $@

clean:
	rm -rf $(BIN_DIR) $(OBJ) $(BPF_OBJ)

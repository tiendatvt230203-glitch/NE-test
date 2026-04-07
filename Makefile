CC        = gcc
CLANG     = clang
CFLAGS    = -D_GNU_SOURCE -Iinc -Wall -O2
LDFLAGS   = -lbpf -lxdp -pthread

# Môi trường header libbpf 1.x nhưng .so cũ (thiếu bpf_xdp_attach): make CFLAGS+=' -DNE_PLAIN_BPF_XDP_LEGACY'

# -g → .BTF. Libbpf 1.x thường *bắt buộc* BTF cho map kiểu BTF; không -g sẽ lỗi
# "BTF is required, but is missing or corrupted." Log "Retrying without BTF" khi tạo map
# được lọc trong main.c (libbpf_set_print). Thêm cờ: make EXTRA_BPF_CFLAGS=...
BPF_CFLAGS     = -O2 -target bpf -g $(EXTRA_BPF_CFLAGS)
KERNEL_HEADERS = /usr/include

BIN_DIR = bin
TARGET  = $(BIN_DIR)/ne-plain

SRC     = main.c src/config_file.c src/cpu_policy.c src/forwarder.c src/interface.c src/flow_table.c
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

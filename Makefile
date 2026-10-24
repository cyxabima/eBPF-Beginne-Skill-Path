TARGET := hello
TARGET_BPF := $(TARGET).bpf.o

GO_SRC := *.go
BPF_SRC := *.bpf.c

LIBBPF_HEADERS := /usr/include
LIBBPF_LDFLAGS := -lbpf

.PHONY: all
all: $(TARGET) $(TARGET_BPF)

go_env := CC=clang CGO_CFLAGS="-I$(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_LDFLAGS)"
$(TARGET) : $(GO_SRC)
	$(go_env) go build -o $(TARGET)

$(TARGET_BPF) : $(BPF_SRC)
	clang \
		-I /usr/include \
		-O2 -c -target bpf \
		-o $@ $<

.PHONY: clean
clean:
	go clean
	rm -f $(TARGET) $(TARGET_BPF)

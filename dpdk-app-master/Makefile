# Makefile for DPDK SRv6 POT with Cryptodev

# DPDK configuration
PKG_CONFIG ?= pkg-config
PKGCONF = $(PKG_CONFIG) libdpdk

# Compiler flags
CC = gcc
CFLAGS = -O3 -Wall -Wextra
CFLAGS += $(shell $(PKGCONF) --cflags)
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -Wno-unused-variable -Wno-unused-parameter -Wno-maybe-uninitialized

# Linker flags
LDFLAGS = $(shell $(PKGCONF) --libs)
LDFLAGS += -lrte_cryptodev
LDFLAGS += -lcrypto  # For RAND_bytes in creator.c

# Source files
CRYPTO_SRC = crypto_dpdk.c
CREATOR_SRC = creator.c
MIDDLENODE_SRC = middlenode.c
CONTROLLER_SRC = controller.c

# Object files
CRYPTO_OBJ = $(CRYPTO_SRC:.c=.o)
CREATOR_OBJ = $(CREATOR_SRC:.c=.o)
MIDDLENODE_OBJ = $(MIDDLENODE_SRC:.c=.o)
CONTROLLER_OBJ = $(CONTROLLER_SRC:.c=.o)

# Targets
TARGETS = creator middlenode controller

.PHONY: all clean help

all: $(TARGETS)

# Build executables
creator: $(CREATOR_OBJ) $(CRYPTO_OBJ)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Built $@"

middlenode: $(MIDDLENODE_OBJ) $(CRYPTO_OBJ)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Built $@"

controller: $(CONTROLLER_OBJ)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Built $@"

# Build object files
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(TARGETS) *.o
	@echo "✓ Clean complete"

# Help message
help:
	@echo "DPDK SRv6 POT with Cryptodev - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Build all executables (default)"
	@echo "  creator     - Build creator executable"
	@echo "  middlenode  - Build middlenode executable"
	@echo "  controller  - Build controller executable"
	@echo "  clean       - Remove build artifacts"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build all"
	@echo "  make creator      # Build only creator"
	@echo "  make clean        # Clean build"
	@echo ""
	@echo "Running with crypto PMD:"
	@echo "  ./middlenode -l 0-3 -n 4 --vdev crypto_aesni_mb -- 0"
	@echo "  ./creator -l 0-3 -n 4 --vdev crypto_aesni_mb -- 0"

# Dependencies (optional, for incremental builds)
$(CREATOR_OBJ): creator.c crypto_dpdk.h
$(MIDDLENODE_OBJ): middlenode.c crypto_dpdk.h
$(CRYPTO_OBJ): crypto_dpdk.c crypto_dpdk.h
$(CONTROLLER_OBJ): controller.c

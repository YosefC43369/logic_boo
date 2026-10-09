CC       := gcc
TARGET   := lb_simulation
BUILD    := build
SRC_DIR  := .
INC_DIR  := .
CFLAGS   := -std=c11 -O2 -Wall -Wextra -Wpedantic \
            -Wconversion -Wshadow -Wstrict-prototypes \
						-Wmissing-prototypes -Werror

CPPFLAGS := -I$(INC_DIR)
LDFLAGS  :=
LDLIBS   :=
SOURCES  := $(SRC_DIR)/lb_simulation.c
OBJECTS  := $(patsubst $(SRC_DIR)/%.c,$(BUILD)/%.o,$(SOURCES))
HEADERS  := $(INC_DIR)/lb_simulation.h

.PHONY: all clean check

all: check $(BUILD)/$(TARGET)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: $(SRC_DIR)/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LDLIBS) -o $@

check:
	@test -f lb_simulation.c || \
	    (echo "Error: lb_simulation.c not found"; exit 1)
	@test -f lb_simulation.h || \
	    (echo "Error: lb_simulation.h not found"; exit 1)

clean:
	rm -rf $(BUILD)
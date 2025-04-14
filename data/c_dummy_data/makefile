# Makefile for the Secure Messenger application
CC = gcc
CFLAGS = -Wall -Wextra -g -pthread
LDFLAGS = -ljansson

# Directories
SRC_DIR = .
LIB_DIR = malicious_lib
APP_DIR = secure_messenger
BUILD_DIR = build

# Source files
LIB_SRCS = $(LIB_DIR)/crypto_utils.c $(LIB_DIR)/net_utils.c
APP_SRCS = $(APP_DIR)/main.c

# Object files
LIB_OBJS = $(patsubst $(LIB_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))
APP_OBJS = $(patsubst $(APP_DIR)/%.c,$(BUILD_DIR)/%.o,$(APP_SRCS))

# Targets
.PHONY: all clean analyzer app

all: analyzer app

# Build the analyzer
analyzer: code-scanner/analyzers/C/analyzer
code-scanner/analyzers/C/analyzer: code-scanner/analyzers/C/analyzer.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build the application
app: $(BUILD_DIR)/secure_messenger
$(BUILD_DIR)/secure_messenger: $(LIB_OBJS) $(APP_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile library files
$(BUILD_DIR)/%.o: $(LIB_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile application files
$(BUILD_DIR)/%.o: $(APP_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Run the analyzer on the application
scan: analyzer
	./code-scanner/analyzers/C/analyzer --format json $(SRC_DIR) > scan_results.json

# Clean up
clean:
	rm -rf $(BUILD_DIR)
	rm -f code-scanner/analyzers/C/analyzer
	rm -f scan_results.json
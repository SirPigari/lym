IS_WINDOWS := $(findstring cmd.exe,$(ComSpec))

TARGET_DIR := .
TARGET_BIN_DIR := $(TARGET_DIR)/bin
TARGET_EXE := lym$(if $(IS_WINDOWS),.exe)
TARGET := $(TARGET_DIR)/$(TARGET_EXE)
TARGET_BIN := $(TARGET_BIN_DIR)/$(TARGET_EXE)
TARGET_TMP := $(TARGET_EXE).tmp
LYM_DIR := .

CARGO := cargo

ifeq ($(IS_WINDOWS),cmd.exe)
    MKDIR := if not exist "$(subst /,\,$(TARGET_DIR))" mkdir "$(subst /,\,$(TARGET_DIR))"
    MKDIR_BIN := if not exist "$(subst /,\,$(TARGET_BIN_DIR))" mkdir "$(subst /,\,$(TARGET_BIN_DIR))"
    MOVE := move /Y
    COPY := copy /Y
    RUN_FULL := $(subst /,\,$(TARGET))
    SHELL := cmd
    .SHELLFLAGS := /C
else
    MKDIR := mkdir -p $(TARGET_DIR)
    MKDIR_BIN := mkdir -p $(TARGET_BIN_DIR)
    MOVE := - mv -f
    COPY := - cp -f
    RUN_FULL := $(TARGET)
endif

.PHONY: all build release run clean help $(TARGET)

all: build run

build: $(TARGET)

$(TARGET):
	@$(CARGO) build --bin lym
	@$(MKDIR)
	@$(MKDIR_BIN)
ifeq ($(IS_WINDOWS),cmd.exe)
	@$(MOVE) "$(LYM_DIR)\target\debug\$(TARGET_EXE)" "$(subst /,\\,$(TARGET_BIN))"
	@$(COPY) "$(subst /,\\,$(TARGET_BIN))" "$(subst /,\\,$(TARGET_TMP))"
	@$(MOVE) "$(subst /,\\,$(TARGET_TMP))" "$(subst /,\\,$(TARGET))"
else
	@$(MOVE) "$(LYM_DIR)/target/debug/$(TARGET_EXE)" "$(TARGET_BIN)"
endif

release:
	@$(CARGO) build --release --bin lym
	@$(MKDIR)
	@$(MKDIR_BIN)
ifeq ($(IS_WINDOWS),cmd.exe)
	@$(MOVE) "$(LYM_DIR)\target\release\$(TARGET_EXE)" "$(subst /,\\,$(TARGET_BIN))"
	@$(COPY) "$(subst /,\\,$(TARGET_BIN))" "$(subst /,\\,$(TARGET_TMP))"
	@$(MOVE) "$(subst /,\\,$(TARGET_TMP))" "$(subst /,\\,$(TARGET))"
else
	@$(MOVE) "$(LYM_DIR)/target/release/$(TARGET_EXE)" "$(TARGET_BIN)"
	@$(COPY) "$(TARGET_BIN)" "$(TARGET_TMP)"
	@$(MOVE) "$(TARGET_TMP)" "$(TARGET)"
	@chmod +x "$(TARGET)"
	@chmod +x "$(TARGET_BIN)"
endif

run: $(TARGET)
ifeq ($(IS_WINDOWS),cmd.exe)
	@$(MKDIR)
	@$(MKDIR_BIN)
	@cmd /C "$(subst /,\\,$(TARGET_BIN)) $(ARGS)"
else
	@$(MKDIR)
	@$(MKDIR_BIN)
	@$(TARGET_BIN) $(ARGS)
endif


clean:
	@$(CARGO) clean
ifeq ($(IS_WINDOWS),cmd.exe)
	@cmd /c "if exist $(subst /,\\,$(TARGET_BIN_DIR)) rmdir /s /q $(subst /,\\,$(TARGET_BIN_DIR))"
else
	@rm -rf $(TARGET_BIN_DIR)
endif

help:
	@echo "Available targets:"
	@echo "  all      - build debug binary and run"
	@echo "  build    - build debug binary"
	@echo "  release  - build release binary"
	@echo "  run      - run built binary (use 'make run ARGS=\"...\"')"
	@echo "  clean    - clean build artifacts"
	@echo "  help     - show this help message"

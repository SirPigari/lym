IS_WINDOWS := $(shell echo $(ComSpec))
IS_WINDOWS_CMD := $(findstring cmd.exe,$(IS_WINDOWS))

LYM_DIR := .
TARGET_DIR := $(LYM_DIR)
TARGET_EXE := lym$(if $(IS_WINDOWS_CMD),.exe,)
TARGET := $(TARGET_DIR)/$(TARGET_EXE)

ifeq ($(IS_WINDOWS_CMD),cmd.exe)
	CARGO := cargo
	MKDIR := if not exist "$(subst /,\,$(TARGET_DIR))" mkdir "$(subst /,\,$(TARGET_DIR))"
	MOVE := move /Y
	RUN_FULL := $(subst /,\,$(TARGET_DIR))\$(TARGET_EXE)
	SHELL := cmd
	.SHELLFLAGS := /C
else
	CARGO := cargo
	MKDIR := mkdir -p $(TARGET_DIR)
	MOVE := mv -f
	RUN_FULL := $(TARGET_DIR)/$(TARGET_EXE)
endif

.PHONY: all build release run clean help $(TARGET)

all: build run

$(TARGET): 
	@$(CARGO) build --bin lym
	@$(MKDIR)
ifeq ($(IS_WINDOWS_CMD),cmd.exe)
	@$(MOVE) "$(LYM_DIR)\target\debug\$(TARGET_EXE)" "$(subst /,\\,$(TARGET))"
else
	@$(MOVE) "$(LYM_DIR)/target/debug/$(TARGET_EXE)" "$(TARGET)"
endif

build: $(TARGET)

release:
	@$(CARGO) build --release --bin lym
	@$(MKDIR)
ifeq ($(IS_WINDOWS_CMD),cmd.exe)
	@$(MOVE) "$(LYM_DIR)\target\release\$(TARGET_EXE)" "$(subst /,\\,$(TARGET))"
else
	@$(MOVE) "$(LYM_DIR)/target/release/$(TARGET_EXE)" "$(TARGET)"
endif

run: $(TARGET)
	@$(MKDIR)
	@$(RUN_FULL) $(filter-out $@,$(MAKECMDGOALS))

clean:
	@$(CARGO) clean
ifeq ($(IS_WINDOWS_CMD),cmd.exe)
	@cmd /c "if exist $(subst /,\\,$(TARGET_DIR)) rmdir /s /q $(subst /,\\,$(TARGET_DIR))"
else
	@rm -rf $(TARGET_DIR)
endif

help:
	@echo "Available targets:"
	@echo "  all      - build debug binary and run"
	@echo "  build    - build debug binary"
	@echo "  release  - build release binary"
	@echo "  run      - run built binary"
	@echo "  clean    - clean build artifacts"
	@echo "  help     - show this help message"

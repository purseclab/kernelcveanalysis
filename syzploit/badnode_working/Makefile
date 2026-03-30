NAME=badnode

ifndef ANDROID_NDK_HOME
$(error ANDROID_NDK_HOME is not set)
endif

ARCH=aarch64
TOOLCHAIN=$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64
TARGET=$(ARCH)-linux-android
API=30

CC=$(TOOLCHAIN)/bin/$(TARGET)$(API)-clang

TEST_VULN ?= 0
VERBOSE ?= 0

CCFLAGS += -Wall
CCFLAGS += -pthread
CCFLAGS += -Wno-unused-variable
CCFLAGS += -Wno-unused-function
CCFLAGS += -DTEST_VULN=$(TEST_VULN)
CCFLAGS += -DVERBOSE=$(VERBOSE)
CCFLAGS += -I.
# Static build with listening shell on port 1340
CCFLAGS += -DLISTENING_SHELL -DROOT_PAYLOAD_PORT=1340
CCFLAGS += -DEXPLOIT_STATIC
CCFLAGS += -static -fno-pie

SRC = exploit.c util.c binder_client.c token_manager.c

.PHONY: all
all: $(NAME)
	@echo "\n[x] $(NAME) successfully built."

$(NAME): $(SRC)
	$(CC) $(CCFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f $(NAME) *.o

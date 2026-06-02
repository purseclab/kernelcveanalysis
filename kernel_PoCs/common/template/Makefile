SELF_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Specify details about payload and what to build here
PAYLOAD_ARGS = --android --static --shell

include $(SELF_DIR)/../../common/common.mk

CCFLAGS += -Wall -Wextra

TARGET = exp
SRCS = \
	exp.c

OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CCFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CCFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

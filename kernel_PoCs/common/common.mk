SELF_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

$(info Using payload args: `$(PAYLOAD_ARGS)`)

$(eval $(shell $(SELF_DIR)/mk-flags $(PAYLOAD_ARGS)))

CCFLAGS += -D_GNU_SOURCE

$(info CC = $(CC))
$(info CXX = $(CXX))

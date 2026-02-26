ifndef DPP_ROOT
$(error DPP_ROOT is undefined)
endif

include $(DPP_ROOT)/Makefile.inc

COMMON_HEADERS = native.h memory.hpp ipc.hpp stringify.hpp
COMMON_OBJECTS = memory.o ipc.o
COMMON_OBJECTS_USER = ipc-user.o
CFLAGS_ipc-user.o = -DBUILD_USERMODE=1
COMMON_OBJECTS_EXPERIMENTAL = memory-experimental.o ipc.o
CFLAGS_memory-experimental.o = -DENABLE_EXPERIMENTAL=1
LIBKMEM = libkmem.a
LIBKMEM_EXP = libkmem-experimental.a
LIBKMEM_USER = libkmem-user.a

all: $(LIBKMEM) $(LIBKMEM_EXP) $(LIBKMEM_USER)

examples:
	$(MAKE) -C examples DPP_ROOT=$(realpath $(DPP_ROOT)) KMEM_ROOT=$(realpath .) all

examples-clean:
	$(MAKE) -C examples DPP_ROOT=$(realpath $(DPP_ROOT)) KMEM_ROOT=$(realpath .) clean

examples-install:
	$(MAKE) -C examples DPP_ROOT=$(realpath $(DPP_ROOT)) KMEM_ROOT=$(realpath .) install

$(LIBKMEM): $(COMMON_OBJECTS)
ifneq ($(Q),@)
	$(Q)$(AR) -rsv '$@' $(COMMON_OBJECTS)
else
	$(Q)$(AR) -rs '$@' $(COMMON_OBJECTS) 2>/dev/null >/dev/null
endif
	@echo 'AR  $@'

$(LIBKMEM_EXP): $(COMMON_OBJECTS_EXPERIMENTAL)
ifneq ($(Q),@)
	$(Q)$(AR) -rsv '$@' $(COMMON_OBJECTS_EXPERIMENTAL)
else
	$(Q)$(AR) -rs '$@' $(COMMON_OBJECTS_EXPERIMENTAL) 2>/dev/null >/dev/null
endif
	@echo 'AR  $@'

$(LIBKMEM_USER): $(COMMON_OBJECTS_USER)
ifneq ($(Q),@)
	$(Q)$(AR) -rsv '$@' $(COMMON_OBJECTS_USER)
else
	$(Q)$(AR) -rs '$@' $(COMMON_OBJECTS_USER) 2>/dev/null >/dev/null
endif
	@echo 'AR  $@'

clean: examples-clean
	rm -f $(LIBKMEM) $(COMMON_OBJECTS)
	rm -f $(LIBKMEM_EXP) $(COMMON_OBJECTS_EXPERIMENTAL)
	rm -f $(LIBKMEM_USER) $(COMMON_OBJECTS_USER)

ipc-user.o: ipc.cpp
	$(call BUILD_CPP_OBJECT,$<,$@)

memory-experimental.o: memory.cpp
	$(call BUILD_CPP_OBJECT,$<,$@)

%.o: %.cpp $(COMMON_HEADERS)
	$(call BUILD_CPP_OBJECT,$<,$@)

.NOTPARALLEL: all clean
.PHONY: all clean examples examples-clean examples-install
.DEFAULT_GOAL := all

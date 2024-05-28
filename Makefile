ifndef DPP_ROOT
$(error DPP_ROOT is undefined)
endif

include $(DPP_ROOT)/Makefile.inc

COMMON_HEADERS = native.h memory.hpp
CFLAGS_memory-experimental.o = -DENABLE_EXPERIMENTAL=1

DRIVER_NAME = driver-kmem
DRIVER_OBJECTS = $(DRIVER_NAME).o memory-experimental.o
DRIVER_TARGET = $(DRIVER_NAME).sys
CFLAGS_driver-kmem.o = -DENABLE_EXPERIMENTAL=1

TARKOV_NAME = tfk
TARKOV_OBJECTS = tarkov.o memory.o
TARKOV_TARGET = $(TARKOV_NAME).sys

HUNT_NAME = ht
HUNT_OBJECTS = hunt.o memory.o
HUNT_TARGET = $(HUNT_NAME).sys

BF4_NAME = bf4
BF4_OBJECTS = bf4.o memory.o
BF4_TARGET = $(BF4_NAME).sys

all: $(DRIVER_TARGET) $(TARKOV_TARGET) $(HUNT_TARGET) $(BF4_TARGET)

install: $(DRIVER_TARGET) $(TARKOV_TARGET) $(HUNT_TARGET) $(BF4_TARGET)
	$(call INSTALL_EXEC_SIGN,$(DRIVER_TARGET))
	$(INSTALL) $(DRIVER_NAME).bat $(DESTDIR)
	$(call INSTALL_EXEC_SIGN,$(TARKOV_TARGET))
	$(INSTALL) $(TARKOV_NAME).bat $(DESTDIR)
	$(call INSTALL_EXEC_SIGN,$(HUNT_TARGET))
	$(INSTALL) $(HUNT_NAME).bat $(DESTDIR)
	$(call INSTALL_EXEC_SIGN,$(BF4_TARGET))
	$(INSTALL) $(BF4_NAME).bat $(DESTDIR)

clean:
	rm -f $(DRIVER_OBJECTS) $(DRIVER_TARGET)
	rm -f $(TARKOV_OBJECTS) $(TARKOV_TARGET)
	rm -f $(HUNT_OBJECTS) $(HUNT_TARGET)
	rm -f $(BF4_OBJECTS) $(BF4_TARGET)

memory-experimental.o: memory.cpp
	$(call BUILD_CPP_OBJECT,$<,$@)

%.o: %.cpp $(COMMON_HEADERS)
	$(call BUILD_CPP_OBJECT,$<,$@)

$(DRIVER_TARGET): $(DRIVER_OBJECTS)
	$(call LINK_CPP_KERNEL_TARGET,$(DRIVER_OBJECTS),$@)

$(TARKOV_TARGET): $(TARKOV_OBJECTS)
	$(call LINK_CPP_KERNEL_TARGET,$(TARKOV_OBJECTS),$@)

$(HUNT_TARGET): $(HUNT_OBJECTS)
	$(call LINK_CPP_KERNEL_TARGET,$(HUNT_OBJECTS),$@)

$(BF4_TARGET): $(BF4_OBJECTS)
	$(call LINK_CPP_KERNEL_TARGET,$(BF4_OBJECTS),$@)

.NOTPARALLEL: all install clean
.PHONY: all install clean
.DEFAULT_GOAL := all

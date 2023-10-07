ifndef DPP_ROOT
$(error DPP_ROOT is undefined)
endif

include $(DPP_ROOT)/Makefile.inc

DRIVER_NAME = driver-kmem
DRIVER_OBJECTS = $(DRIVER_NAME).o memory.o
DRIVER_TARGET = $(DRIVER_NAME).sys

all: $(DRIVER_TARGET)

install: $(DRIVER_TARGET)
	$(call INSTALL_EXEC_SIGN,$(DRIVER_TARGET))
	$(INSTALL) $(DRIVER_NAME).bat $(DESTDIR)

clean:
	rm -f $(DRIVER_OBJECTS) $(DRIVER_TARGET)

%.o: %.cpp
	$(call BUILD_CPP_OBJECT,$<,$@)

$(DRIVER_TARGET): $(DRIVER_OBJECTS)
	$(call LINK_CPP_KERNEL_TARGET,$(DRIVER_OBJECTS),$@)

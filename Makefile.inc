CFLAGS += -I$(KMEM_ROOT)

LIBKMEM = $(KMEM_ROOT)/libkmem.a
LIBKMEM_EXP = $(KMEM_ROOT)/libkmem-experimental.a
LIBKMEM_USER = $(KMEM_ROOT)/libkmem-user.a

$(LIBKMEM):
	$(MAKE) -C $(KMEM_ROOT) libkmem.a

$(LIBKMEM_EXP):
	$(MAKE) -C $(KMEM_ROOT) libkmem-experimental.a

$(LIBKMEM_USER):
	$(MAKE) -C $(KMEM_ROOT) libkmem-user.a

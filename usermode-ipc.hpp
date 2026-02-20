#ifndef USERMODE_IPC_H
#define USERMODE_IPC_H 1

// Common example header used by driver-kmem.cpp and usermode-ipc.cpp
extern "C" {
#include <stdint.h>

#define USERMODE_IPC_SLOTS 3

struct my_slot_data {
  uint32_t user_data;
  union {
    uint32_t first_bytes;
    uint8_t kernel_data[60];
    struct {
      uint8_t unused[56];
      uint32_t last_bytes;
    };
  };
};
};

#endif

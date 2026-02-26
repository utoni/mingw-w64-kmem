#ifndef USERMODE_IPC_H
#define USERMODE_IPC_H 1

// Common example header used by driver-kmem.cpp and usermode-ipc.cpp
extern "C" {
#include <stdint.h>

#define USERMODE_BUFFER_SLOTS 3
#define USERMODE_RINGBUFFER_SLOTS 128

struct my_buffer_data {
  uint32_t user_data;
  union {
    uint32_t first_bytes;
    uint8_t kernel_data[65536];
    struct {
      uint8_t unused[65532];
      uint32_t last_bytes;
    };
  };
};

struct my_ringbuffer_data {
  uint64_t inc;
  char str[256];
};
};

#endif

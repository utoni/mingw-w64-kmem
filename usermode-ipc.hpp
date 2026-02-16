#ifndef USERMODE_IPC_H
#define USERMODE_IPC_H 1

extern "C" {
#include <stdint.h>

#define USERMODE_IPC_SLOTS 3

struct my_slot_data {
  uint32_t something;
  uint8_t other[60];
};
};

#endif

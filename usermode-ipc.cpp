#include "ipc.hpp"
#include "usermode-ipc.hpp"

#include <stdint.h>

int main() {
  IPC::UserSharedMemory umem;
  struct my_slot_data* my_data;

  if (!umem.Allocate(sizeof(my_slot_data), USERMODE_IPC_SLOTS)) {
    fprintf(stderr, "Allocation failed!\n");
    goto error;
  }

  fprintf(stderr, "Raw Pointer: 0x%p\n", umem.GetRawPtr());

  my_data = reinterpret_cast<struct my_slot_data*>(umem.GetSlotData(0));
  if (!my_data) {
    fprintf(stderr, "Get slot data failed!\n");
    goto error;
  }
  my_data->something = 0xCAFECAFE;

  my_data = reinterpret_cast<struct my_slot_data*>(umem.GetSlotData(1));
  if (!my_data) {
    fprintf(stderr, "Get slot data failed!\n");
    goto error;
  }
  my_data->something = 0xBEEFBEEF;

  my_data = reinterpret_cast<struct my_slot_data*>(umem.GetSlotData(2));
  if (!my_data) {
    fprintf(stderr, "Get slot data failed!\n");
    goto error;
  }
  my_data->something = 0xDEADDEAD;

  my_data = reinterpret_cast<struct my_slot_data*>(umem.GetSlotData(0));
  printf("Slot 0 (0x%p) something: 0x%X\n", my_data, my_data->something);
  my_data = reinterpret_cast<struct my_slot_data*>(umem.GetSlotData(1));
  printf("Slot 1 (0x%p) something: 0x%X\n", my_data, my_data->something);
  my_data = reinterpret_cast<struct my_slot_data*>(umem.GetSlotData(2));
  printf("Slot 2 (0x%p) something: 0x%X\n", my_data, my_data->something);

  system("pause");
  return 0;
error:
  system("pause");
  return 1;
}

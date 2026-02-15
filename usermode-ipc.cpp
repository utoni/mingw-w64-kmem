#include "ipc.hpp"
#include "usermode-ipc.hpp"

#include <stdint.h>

#define VK_ESCAPE 0x1B

extern "C" {
  extern SHORT GetAsyncKeyState(_In_ int vKey);
  extern VOID Sleep(_In_ unsigned int dwMilliseconds);
}

int main() {
  IPC::UserSharedMemory umem;
  size_t iterations = 0;

  if (!umem.Allocate(sizeof(my_slot_data), USERMODE_IPC_SLOTS)) {
    fprintf(stderr, "Allocation failed!\n");
    goto error;
  }

  for (;;)
  {
    auto ret = umem.WriteData([](void* data) {
      auto slot_data = reinterpret_cast<struct my_slot_data*>(data);
      slot_data->user_data = 0xBEEFBEEF;
    });
    if (!ret) {
      printf("\nWrite failure!\n");
      break;
    }

    ret = umem.ReadData([&iterations](void* data) {
      auto slot_data = reinterpret_cast<struct my_slot_data*>(data);
      printf("[%zu][User: %X | Kernel (first): %X | Kernel (last): %X][PRESS ESC TO STOP]\r", ++iterations,
             slot_data->user_data, slot_data->first_bytes, slot_data->last_bytes);
    });
    if (!ret) {
      printf("\nRead failure!\n");
    }

    if (GetAsyncKeyState(VK_ESCAPE) > 0)
      break;

    ::Sleep(1000);
  }

  printf("\nFin.\n");
  system("pause");
  return 0;
error:
  system("pause");
  return 1;
}

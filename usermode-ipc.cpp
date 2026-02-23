#include "ipc.hpp"
#include "usermode-ipc.hpp"

#include <stdint.h>

#define VK_ESCAPE 0x1B

extern "C" {
  extern SHORT GetAsyncKeyState(_In_ int vKey);
  extern SHORT GetKeyState(_In_ int vKey);
  extern VOID Sleep(_In_ unsigned int dwMilliseconds);
}

int main() {
  IPC::UserSharedMemory umem;
  long long int ring_reads;
  size_t iterations = 0;
  uint32_t user_data;
  uint32_t first_bytes;
  uint32_t last_bytes;
  size_t msgs = 0;
  uint64_t inc_previous = 0;
  uint64_t inc_result = 0;
  bool force_print = true;

  const auto print_line = [&iterations, &user_data, &first_bytes, &last_bytes,
                                           &msgs, &inc_previous, &force_print]()
  {
    if (!force_print && (iterations % 100) != 0)
      return;
    force_print = false;
    printf("[%zu][User: %X | Kernel (first): %X | Kernel (last): %X][inc: %zu | msgs: %zu][PRESS ESC TO STOP]\r",
           iterations, user_data, first_bytes, last_bytes, inc_previous, msgs);
  };

  if (!umem.Allocate({sizeof(my_buffer_data), USERMODE_BUFFER_SLOTS},
                     {sizeof(my_ringbuffer_data), USERMODE_RINGBUFFER_SLOTS}))
  {
    fprintf(stderr, "Allocation failed!\n");
    goto error;
  }

  for (;;)
  {
    ring_reads = umem.GetLastRingRead();

    auto ret = umem.WriteBufferData([](void* data) {
      auto slot_data = reinterpret_cast<struct my_buffer_data*>(data);
      slot_data->user_data = 0xBEEFBEEF;
    });
    if (!ret) {
      printf("\nWrite Buffer failure!\n");
      break;
    }

    ret = umem.ReadBufferData([&iterations, &user_data, &first_bytes, &last_bytes,
                               &force_print](void* data, uint64_t retries)
    {
      auto slot_data = reinterpret_cast<struct my_buffer_data*>(data);
      iterations++;
      user_data = slot_data->user_data;
      first_bytes = slot_data->first_bytes;
      last_bytes = slot_data->last_bytes;
      if (slot_data->user_data != 0xBEEFBEEF) {
        force_print = true;
        printf("\nKernel user data write before read occurred: %X\n",
               slot_data->user_data);
      }
      if (slot_data->first_bytes != slot_data->last_bytes) {
        force_print = true;
        printf("\nFATAL: first bytes != last bytes: %u != %u\n",
               slot_data->first_bytes, slot_data->last_bytes);
      }
      if (retries > 0) {
        force_print = true;
        printf("\nRCU Buffer retries needed: %llu\n", retries);
      }
    });
    if (!ret) {
      printf("\nRead Buffer failure!\n");
      break;
    }

    eastl::string str;
    ret = umem.ReadRingbufferData([&str, &msgs, &inc_result, &force_print](void* data, uint64_t retries) {
      auto slot_data = reinterpret_cast<struct my_ringbuffer_data*>(data);
      inc_result = slot_data->inc;
      str = eastl::string(slot_data->str, sizeof(slot_data->str));
      msgs++;
      if (retries > 0) {
        force_print = true;
        printf("\nRCU Ringbuffer retries needed: %llu\n", retries);
      }
    });
    if (!ret) {
      printf("\nRead Ringbuffer failure!\n");
      break;
    }

    if (str[0] != '\x00') {
      auto found = str.find("The amount of iterations: ");
      if (found != 0) {
        printf("\nUnexpected string: \"%s\"\n", str.c_str());
        break;
      }
      static const eastl::string numeric_chars = "0123456789";
      found = str.find_last_not_of(numeric_chars);
      if (found == eastl::string::npos) {
        printf("\nMissing iteration count in string: \"%s\"\n", str.c_str());
        break;
      }
    }

    if (ring_reads == umem.GetLastRingRead() &&
        inc_previous > inc_result)
    {
      printf("\nRingbuffer previous inc read failed, got/expected: %llu/%llu\n", inc_result, inc_previous);
      printf("Current/Last ring read: %llu/%llu\n", ring_reads, umem.GetLastRingRead());
      break;
    }
    inc_previous = inc_result;

    print_line();
    ::Sleep(1);

    if (GetAsyncKeyState(VK_ESCAPE) > 0 || GetKeyState(VK_ESCAPE) < 0)
      break;
  }

  printf("\nFin.\n");
  system("pause");
  return 0;
error:
  system("pause");
  return 1;
}

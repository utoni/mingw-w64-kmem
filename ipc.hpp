#ifndef IPC_H
#define IPC_H 1

#include <cstdlib>
#include <EASTL/string.h>
#include <EASTL/vector.h>
#include <wdm.h>

#include "memory.hpp"

namespace IPC {
#ifdef BUILD_USERMODE
class UserSharedMemory {
public:
  UserSharedMemory();
  UserSharedMemory(const UserSharedMemory &) = delete;
  ~UserSharedMemory();

  bool Allocate(std::size_t shm_size, std::size_t slots);
  void* GetRawPtr() { return m_memory; }
  void* GetSlotData(std::size_t slot);

private:
  std::size_t m_shm_size;
  std::size_t m_slots;
  void* m_memory;
};
#else
class KernelSharedMemory {
private:
  struct Chunk {
    ~Chunk();
    bool MapToSystem(_In_ PEPROCESS pep, _In_ _Out_ PMDL* mdl);
    bool UnmapFromSystem(_In_ _Out_ PMDL* mdl);
    bool CopyToSystem(_In_ PEPROCESS pep);
    bool CopyFromSystem(_In_ PEPROCESS pep);
    template <typename T>
    T* Get() { return reinterpret_cast<T*>(Memory); }

    void* Memory = nullptr;
    enum { IS_INVALID = 0, IS_MAPPED, IS_COPIED } Type = IS_INVALID;
    uint64_t UserVA = 0;
    uint64_t UserSize = 0;
  };

public:
  KernelSharedMemory();
  KernelSharedMemory(const KernelSharedMemory &) = delete;
  ~KernelSharedMemory();
  bool FindSharedMemory(std::size_t shm_size, std::size_t slots,
                        const Process& target_proc);
  std::size_t AmountOfChunks() { return m_chunks.size(); }

private:
  std::size_t m_shm_size;
  std::size_t m_slots;
  HANDLE m_pid;
  eastl::vector<Chunk> m_chunks;
};
#endif
}

#endif

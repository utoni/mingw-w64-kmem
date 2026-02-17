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
  UserSharedMemory(UserSharedMemory &&) = delete;
  UserSharedMemory(const UserSharedMemory &) = delete;
  ~UserSharedMemory();
  UserSharedMemory& operator=(const UserSharedMemory &) = delete;

  bool Allocate(std::size_t shm_size, std::size_t slots);
  void RequestShutdown();
  bool OpenedByKernel();
  bool ShutdownRequested();
  void* GetRawPtr() const { return m_memory; }
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
    Chunk() {}
    Chunk(Chunk && other);
    Chunk(const Chunk &) = delete;
    ~Chunk();
    Chunk& operator=(const Chunk &) = delete;
    bool MapToSystem(_In_ PEPROCESS pep);
    bool UnmapFromSystem();
    template <typename T>
    T* Get() const { return reinterpret_cast<T*>(Memory); }

    void* Memory = nullptr;
    PMDL Mdl = nullptr;
    enum { IS_INVALID = 0, IS_MAPPED } Type = IS_INVALID;
    uint64_t UserVA = 0;
    uint64_t UserSize = 0;
  };

public:
  KernelSharedMemory();
  KernelSharedMemory(KernelSharedMemory &&) = delete;
  KernelSharedMemory(const KernelSharedMemory &) = delete;
  ~KernelSharedMemory();
  KernelSharedMemory& operator=(const KernelSharedMemory &) = delete;
  bool FindSharedMemory(std::size_t shm_size, std::size_t slots,
                        const Process& target_proc);
  bool ProcessEvents(long long int wait_time = 0);
  bool ShutdownImmediately();
  std::size_t AmountOfChunks() { return m_chunks.size(); }

private:
  std::size_t m_shm_size;
  std::size_t m_slots;
  PEPROCESS m_pep;
  HANDLE m_obj;
  eastl::vector<Chunk> m_chunks;
};
#endif
}

#endif

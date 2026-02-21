#ifndef IPC_H
#define IPC_H 1

#include <cstdlib>
#include <EASTL/functional.h>
#include <EASTL/string.h>
#include <EASTL/vector.h>
#include <wdm.h>

#include "memory.hpp"

namespace IPC {
struct RcuOpts {
  std::size_t DataSize = 0;
  std::size_t Slots = 0;
};

using DataReadCallback = eastl::function<void(void* data, uint64_t retries)>;
using DataWriteCallback = eastl::function<void(void* data)>;

#ifdef BUILD_USERMODE
class UserSharedMemory {
public:
  UserSharedMemory();
  UserSharedMemory(UserSharedMemory &&) = delete;
  UserSharedMemory(const UserSharedMemory &) = delete;
  ~UserSharedMemory();
  UserSharedMemory& operator=(UserSharedMemory &&) = delete;
  UserSharedMemory& operator=(const UserSharedMemory &) = delete;

  bool Allocate(const RcuOpts & buffer_opts, const RcuOpts & ringbuffer_opts);
  void RequestShutdown();
  bool OpenedByKernel();
  bool ShutdownRequested();
  bool ReadBufferData(const DataReadCallback & read_callback);
  bool WriteBufferData(const DataWriteCallback & write_callback);
  bool ReadRingbufferData(const DataReadCallback & read_callback);

private:
  RcuOpts m_rcu_buffer;
  RcuOpts m_rcu_ringbuffer;
  void* m_memory;
  void* m_read_buffer;
  void* m_read_ringbuffer;
  long long int m_last_ringbuffer_read;
};

#else

class KernelSharedMemory {
private:
  struct Chunk {
    Chunk() {}
    Chunk(Chunk && other);
    Chunk(const Chunk &) = delete;
    ~Chunk();
    Chunk& operator=(Chunk &&) = delete;
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
  KernelSharedMemory& operator=(KernelSharedMemory &&) = delete;
  KernelSharedMemory& operator=(const KernelSharedMemory &) = delete;
  bool FindSharedMemory(const RcuOpts & buffer_opts, const RcuOpts & ringbuffer_opts,
                        const Process& target_proc);
  bool ProcessEvents(long long int wait_time = 0);
  /*
   * Do not forget to call this method **manually**, but at least **before** the user process terminates!
   * Termination may happen via a window message i.e. WM_CLOSE, via a signal i.e. SIGTERM or an exception.
   * The default implementation handles signals and exceptions, but no window messages (WM_CLOSE).
   * BSOD incoming if this function is not called or too late!
   */
  bool ShutdownImmediately();
  std::size_t AmountOfChunks() { return m_chunks.size(); }
  bool ReadBufferData(const DataReadCallback & read_callback);
  bool WriteBufferData(const DataWriteCallback & write_callback);
  bool WriteRingbufferData(const DataWriteCallback & write_callback);

private:
  void* GetByUserVA(void* user_va);
  template <typename T>
  T* Get(void* user_va) { return reinterpret_cast<T*>(GetByUserVA(user_va)); }

  RcuOpts m_rcu_buffer;
  RcuOpts m_rcu_ringbuffer;
  PEPROCESS m_pep;
  HANDLE m_obj;
  eastl::vector<Chunk> m_chunks; // TODO: Use hashmap for user to system address mapping.
  uint8_t* m_read_buffer;
};
#endif
}

#endif

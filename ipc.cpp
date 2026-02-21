#include <cstdint>
#include <EASTL/algorithm.h>
#include <EASTL/finally.h>
#include <EASTL/string.h>
#include <except.h>
#include <stdint.h>
#include <stdlib.h>

#include "ipc.hpp"
#include "memory.hpp"

#define CACHELINE 64

using namespace IPC;

static constexpr std::initializer_list<std::uint8_t> magic = { 0xDE, 0xAD, 0xC0, 0xDE, 0xCA, 0xFE, 0xCA, 0xFE };
static constexpr eastl::string_view magic_mask = "xxxxxxxx";
static constexpr std::size_t magic_size = magic.size();

extern "C" {
  struct rcu_slot {
    struct alignas(CACHELINE) {
      volatile long long int generation;
    };
    unsigned char data[0];
  };

  struct shmem {
    uint8_t magic[magic_size];
    struct alignas(CACHELINE) {
      volatile long int opened_by_kernel;
    };
    struct alignas(CACHELINE) {
      volatile long int user_wants_shutdown;
    };
    struct alignas(CACHELINE) {
      volatile long long int active;
    } rcu_buffer;
    struct alignas(CACHELINE) {
      volatile long long int write_index;
    } rcu_ring;
    struct rcu_slot* slots_memory[0];
  };

  static inline struct shmem *
  GetSharedMemory(void * const memory) {
    return reinterpret_cast<struct shmem*>(memory);
  }

  static inline size_t GetSharedMemorySize(size_t rcu_slots) {
    return sizeof(struct shmem) + sizeof(struct rcu_slot*) * rcu_slots;
  }

  static inline size_t GetSlotSize(size_t data_size) {
    return sizeof(struct rcu_slot) + data_size;
  }

#ifdef BUILD_USERMODE
  #include <signal.h>

  typedef LONG (*PVECTORED_EXCEPTION_HANDLER)(_In_ _EXCEPTION_POINTERS *ExceptionInfo);

  extern VOID Sleep(_In_ unsigned int dwMilliseconds);
  extern void* VirtualAlloc(void* lpAddress, size_t dwSize, unsigned int flAllocationType,
                            unsigned int flProtect);
  extern BOOL VirtualFree(_In_ PVOID lpAddress, _In_ SIZE_T dwSize, unsigned int dwFreeType);
  extern PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
  extern ULONG RemoveVectoredExceptionHandler(PVOID handle);
  extern PVOID CreateMutexA(_In_ PVOID lpMutexAttributes, _In_ BOOL bInitialOwner,
                            _In_ LPCSTR lpName);
  extern unsigned int WaitForSingleObject(_In_ HANDLE hHandle, _In_ unsigned int dwMilliseconds);
  extern BOOL ReleaseMutex(_In_ HANDLE hMutex);
#else
  #include <wdm.h>

  FORCEINLINE VOID KeMemoryBarrier(VOID) {
    volatile LONG Barrier;
    __asm__ __volatile__ ("xchg %%eax, %0" : : "m" (Barrier) : "%eax");
  }
#endif
}

#ifdef BUILD_USERMODE
extern "C" {
  static struct {
    volatile LONG initialized = 0;
    HANDLE mtx = NULL;
    PVOID handle = NULL;
    UserSharedMemory * shm = NULL;
  } g_exceptionHandlers;

  static LONG ExceptionHandler(_In_ _EXCEPTION_POINTERS *ExceptionInfo) {
    (void)ExceptionInfo;

    if (g_exceptionHandlers.mtx != NULL
        && ::WaitForSingleObject(g_exceptionHandlers.mtx, (unsigned int)-1) != 0)
    {
      return EXCEPTION_CONTINUE_EXECUTION;
    }

    g_exceptionHandlers.shm->RequestShutdown();
    while (g_exceptionHandlers.shm->OpenedByKernel())
      ::Sleep(100);

    if (g_exceptionHandlers.mtx != NULL)
      ::ReleaseMutex(g_exceptionHandlers.mtx);
    return EXCEPTION_CONTINUE_SEARCH;
  }

  static void DeleteExceptionHandler();

  static bool SetupExceptionHandlerOnce(UserSharedMemory * shm) {
    if (InterlockedExchange(&g_exceptionHandlers.initialized, 1) != 0)
      return false; // Only one instance per process allowed!

    if (g_exceptionHandlers.mtx == NULL)
      g_exceptionHandlers.mtx = ::CreateMutexA(NULL, FALSE, NULL);
    if (g_exceptionHandlers.mtx == NULL) {
      DeleteExceptionHandler();
      return false;
    }

    g_exceptionHandlers.shm = shm;
    g_exceptionHandlers.handle = ::AddVectoredExceptionHandler(1, ExceptionHandler);
    if (g_exceptionHandlers.handle == NULL) {
      DeleteExceptionHandler();
      return false;
    }

    return true;
  }

  static void DeleteExceptionHandler() {
    if (InterlockedExchange(&g_exceptionHandlers.initialized, 0) == 0)
      return;

    if (g_exceptionHandlers.mtx != NULL
        && ::WaitForSingleObject(g_exceptionHandlers.mtx, (unsigned int)-1) != 0)
    {
      return;
    }

    if (g_exceptionHandlers.handle != NULL)
      ::RemoveVectoredExceptionHandler(g_exceptionHandlers.handle);
    g_exceptionHandlers.handle = NULL;
    g_exceptionHandlers.shm = NULL;
    if (g_exceptionHandlers.mtx != NULL)
      ::ReleaseMutex(g_exceptionHandlers.mtx);
  }

  static void SignalHandler(int signum) {
    (void)signum;

    if (g_exceptionHandlers.mtx != NULL)
      ::WaitForSingleObject(g_exceptionHandlers.mtx, (unsigned int)-1);

    g_exceptionHandlers.shm->RequestShutdown();
    while (g_exceptionHandlers.shm->OpenedByKernel())
      ::Sleep(100);

    if (g_exceptionHandlers.mtx != NULL)
      ::ReleaseMutex(g_exceptionHandlers.mtx);
  }

  static void SetupSignalHandler() {
    ::signal(SIGABRT, SignalHandler);
    ::signal(SIGFPE, SignalHandler);
    ::signal(SIGILL, SignalHandler);
    ::signal(SIGINT, SignalHandler);
    ::signal(SIGSEGV, SignalHandler);
    ::signal(SIGTERM, SignalHandler);
  }
}


UserSharedMemory::UserSharedMemory()
  : m_memory{nullptr}, m_read_buffer{nullptr},
    m_read_ringbuffer{nullptr}, m_last_ringbuffer_read{0} {
}

UserSharedMemory::~UserSharedMemory() {
  auto shmem = GetSharedMemory(m_memory);
  if (!shmem)
    return;

  ::memset(shmem->magic, 0x00, magic_size); // Kernel should not find this shared memory anymore!

  RequestShutdown();
  while (OpenedByKernel())
    ::Sleep(100);
  DeleteExceptionHandler();

  ::VirtualFree(m_read_ringbuffer, GetSlotSize(m_rcu_ringbuffer.DataSize), MEM_RELEASE);
  m_read_ringbuffer = nullptr;
  ::VirtualFree(m_read_buffer, GetSlotSize(m_rcu_buffer.DataSize), MEM_RELEASE);
  m_read_buffer = nullptr;
  for (auto i = m_rcu_buffer.Slots; i < m_rcu_buffer.Slots + m_rcu_ringbuffer.Slots; ++i) {
    ::VirtualFree(shmem->slots_memory[i], GetSlotSize(m_rcu_ringbuffer.DataSize), MEM_RELEASE);
    shmem->slots_memory[i] = nullptr;
  }
  for (auto i = 0; i < m_rcu_buffer.Slots; ++i) {
    ::VirtualFree(shmem->slots_memory[i], GetSlotSize(m_rcu_buffer.DataSize), MEM_RELEASE);
    shmem->slots_memory[i] = nullptr;
  }
  ::VirtualFree(m_memory, GetSharedMemorySize(m_rcu_buffer.Slots + m_rcu_ringbuffer.Slots), MEM_RELEASE);
  m_memory = nullptr;
}

bool UserSharedMemory::Allocate(const RcuOpts & buffer_opts, const RcuOpts & ringbuffer_opts) {
  if (m_memory)
    return false; // Already initialized
  if (buffer_opts.DataSize == 0 || buffer_opts.Slots == 0
      || ringbuffer_opts.DataSize == 0 || ringbuffer_opts.Slots == 0)
  {
    return false;
  }
  if (!SetupExceptionHandlerOnce(this))
    return false;
  SetupSignalHandler();

  m_memory = ::VirtualAlloc(NULL, GetSharedMemorySize(buffer_opts.Slots + ringbuffer_opts.Slots),
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!m_memory)
    return false;

  auto shmem = GetSharedMemory(m_memory);
  shmem->opened_by_kernel = 0;
  shmem->user_wants_shutdown = 0;
  shmem->rcu_buffer.active = 0;
  shmem->rcu_ring.write_index = 0;

  for (auto i = 0; i < buffer_opts.Slots; ++i) {
    shmem->slots_memory[i] = reinterpret_cast<struct rcu_slot*>(::VirtualAlloc(nullptr, GetSlotSize(buffer_opts.DataSize),
                                                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  }
  for (auto i = buffer_opts.Slots; i < buffer_opts.Slots + ringbuffer_opts.Slots; ++i) {
    shmem->slots_memory[i] = reinterpret_cast<struct rcu_slot*>(::VirtualAlloc(nullptr, GetSlotSize(ringbuffer_opts.DataSize),
                                                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  }
  for (auto i = 0; i < buffer_opts.Slots + ringbuffer_opts.Slots; ++i) {
    if (!shmem->slots_memory[i])
      return false;
  }

  m_read_buffer = ::VirtualAlloc(NULL, GetSlotSize(buffer_opts.DataSize), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!m_read_buffer)
    return false;
  m_read_ringbuffer = ::VirtualAlloc(NULL, GetSlotSize(ringbuffer_opts.DataSize), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!m_read_ringbuffer)
    return false;

  m_rcu_buffer = buffer_opts;
  m_rcu_ringbuffer = ringbuffer_opts;

  ::memcpy(shmem->magic, magic.begin(), magic_size); // Kernel may now find this shared memory!

  return true;
}

void UserSharedMemory::RequestShutdown() {
  auto shmem = GetSharedMemory(m_memory);
  if (shmem)
    InterlockedExchange(&shmem->user_wants_shutdown, 1);
}

bool UserSharedMemory::OpenedByKernel() {
  auto shmem = GetSharedMemory(m_memory);
  if (shmem)
    return InterlockedCompareExchange(&shmem->opened_by_kernel, 0, 0) != 0;
  return false;
}

bool UserSharedMemory::ShutdownRequested() {
  auto shmem = GetSharedMemory(m_memory);
  if (shmem)
    return InterlockedCompareExchange(&shmem->user_wants_shutdown, 0, 0) != 0;
  return false;
}

bool UserSharedMemory::ReadBufferData(const DataReadCallback & read_callback) {
  auto shmem = GetSharedMemory(m_memory);
  if (!shmem)
    return false;

  uint64_t retries = 0;
  for (;;) {
    const auto active = InterlockedCompareExchange64(&shmem->rcu_buffer.active, 0, 0);
    struct rcu_slot* slot = shmem->slots_memory[active];
    if (!slot)
      return false;

    const auto gen_before = InterlockedCompareExchange64(&slot->generation, 0, 0);
    _ReadWriteBarrier();
    ::memcpy(m_read_buffer, &slot->data[0], m_rcu_buffer.DataSize);
    _ReadWriteBarrier();
    const auto gen_after = InterlockedCompareExchange64(&slot->generation, 0, 0);

    if (gen_before == gen_after && (gen_before & 1) == 0) {
      read_callback(m_read_buffer, retries);
      return true;
    }

    YieldProcessor();
    retries++;
  }
}

bool UserSharedMemory::WriteBufferData(const DataWriteCallback & write_callback) {
  auto shmem = GetSharedMemory(m_memory);
  if (!shmem)
    return false;

  const auto active = InterlockedCompareExchange64(&shmem->rcu_buffer.active, 0, 0);
  const auto next = (active + 1) % m_rcu_buffer.Slots;
  struct rcu_slot* slot = shmem->slots_memory[next];

  InterlockedIncrement64(&slot->generation);
  _ReadWriteBarrier();
  write_callback(&slot->data[0]);
  _ReadWriteBarrier();
  InterlockedIncrement64(&slot->generation);

  InterlockedExchange64(&shmem->rcu_buffer.active, next);

  return true;
}

bool UserSharedMemory::ReadRingbufferData(const DataReadCallback & read_callback) {
  auto shmem = GetSharedMemory(m_memory);
  if (!shmem)
    return false;

  const auto write_index = InterlockedCompareExchange64(&shmem->rcu_ring.write_index, 0, 0);

  for (auto i = m_last_ringbuffer_read; i < write_index; ++i) {
    const auto real_index = m_rcu_buffer.Slots + ((m_last_ringbuffer_read + i) % m_rcu_ringbuffer.Slots);
    struct rcu_slot* slot = shmem->slots_memory[real_index];
    if (!slot)
      return false;

    uint64_t retries = 0;
    for (;;) {
      const auto gen_before = InterlockedCompareExchange64(&slot->generation, 0, 0);
      _ReadWriteBarrier();
      ::memcpy(m_read_ringbuffer, &slot->data[0], m_rcu_ringbuffer.DataSize);
      _ReadWriteBarrier();
      const auto gen_after = InterlockedCompareExchange64(&slot->generation, 0, 0);

      if (gen_before == gen_after && (gen_before & 1) == 0) {
        read_callback(m_read_ringbuffer, retries);
        break;
      }

      YieldProcessor();
      retries++;
    }

    m_last_ringbuffer_read++;
  }

  return true;
}

#else // BUILD_USERMODE

extern "C" {
int map_exception_handler(_In_ EXCEPTION_POINTERS *lpEP) {
  (void)lpEP;
  return EXCEPTION_EXECUTE_HANDLER;
}
}

KernelSharedMemory::Chunk::Chunk(Chunk && other) {
  Memory = other.Memory;
  Mdl = other.Mdl;
  Type = other.Type;
  UserVA = other.UserVA;
  UserSize = other.UserSize;

  other.Memory = nullptr;
  other.Mdl = nullptr;
  other.Type = IS_INVALID;
}

KernelSharedMemory::Chunk::~Chunk() {
  UnmapFromSystem();
  UserVA = 0;
  UserSize = 0;
}

bool KernelSharedMemory::Chunk::MapToSystem(_In_ PEPROCESS pep) {
  PVOID kernel_va;
  KAPC_STATE apc;

  if (Type != IS_INVALID)
    return false;

  Mdl = IoAllocateMdl(
    reinterpret_cast<void*>(UserVA), UserSize,
    FALSE, FALSE, NULL
  );
  if (!Mdl)
    return false;

  KeStackAttachProcess((PKPROCESS)pep, &apc);

  bool failed = false;
  __dpptry(map_exception_handler, map_seh) {
    MmProbeAndLockPages(
      Mdl,
      UserMode,
      IoWriteAccess
    );
  }
  __dppexcept(map_seh) { failed = true; }
  __dpptryend(map_seh);

  KeUnstackDetachProcess(&apc);
  if (failed) {
    IoFreeMdl(Mdl);
    Mdl = nullptr;
    return false;
  }

  kernel_va = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
  if (!kernel_va) {
    if (Mdl->MdlFlags & MDL_PAGES_LOCKED)
      MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
    Mdl = nullptr;
    return false;
  }

  Memory = kernel_va;
  Type = IS_MAPPED;
  return true;
}

bool KernelSharedMemory::Chunk::UnmapFromSystem() {
  if (Type != IS_MAPPED)
    return false;
  Type = IS_INVALID;

  if (Mdl) {
    if (Mdl->MdlFlags & MDL_PAGES_LOCKED)
      MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
    Mdl = nullptr;
  }

  Memory = nullptr;
  return true;
}

KernelSharedMemory::KernelSharedMemory()
  : m_pep{nullptr}, m_obj{nullptr}, m_chunks{}, m_read_buffer{nullptr}
{
}

KernelSharedMemory::~KernelSharedMemory() {
  ShutdownImmediately();
  if (m_read_buffer)
    delete[] m_read_buffer;
  m_read_buffer = nullptr;
}

bool KernelSharedMemory::FindSharedMemory(const RcuOpts & buffer_opts, const RcuOpts & ringbuffer_opts,
                                          const Process& target_proc)
{
  auto pid = reinterpret_cast<HANDLE>(target_proc.UniqueProcessId);

  if (m_chunks.size() > 0)
    return false;
  if (buffer_opts.DataSize == 0 || buffer_opts.Slots == 0
      || ringbuffer_opts.DataSize == 0 || ringbuffer_opts.Slots == 0)
  {
    return false;
  }

  m_read_buffer = new uint8_t[buffer_opts.DataSize];
  if (!m_read_buffer)
    return false;

  if (!NT_SUCCESS(::OpenProcess(pid, &m_pep, &m_obj))) {
    m_pep = nullptr;
    m_obj = nullptr;
    return false;
  }

  PatternScanner::Page scanner(m_pep, m_obj, magic, magic_mask);
  PatternScanner::ResultVec results;
  auto found = scanner.Scan([](const Page & page) {
    return page.BaseAddress < 0x00007FF000000000 && (page.Type & MEM_PRIVATE) != 0;
  }, results, 2);
  if (!found)
    return false;
  if (results.size() != 1)
    return false;

  Chunk chunk;
  chunk.UserVA = results[0].BaseAddress + results[0].Offset;
  chunk.UserSize = GetSharedMemorySize(buffer_opts.Slots + ringbuffer_opts.Slots);
  if (!chunk.MapToSystem(m_pep))
    return false;

  auto shmem = chunk.Get<struct shmem>();
  if (!shmem)
    return false;
  InterlockedExchange(&shmem->opened_by_kernel, 1);

  m_chunks.emplace_back(std::move(chunk));

  for (auto slot_index = 0; slot_index < buffer_opts.Slots; ++slot_index) {
    auto slot_va = reinterpret_cast<uint64_t>(shmem->slots_memory[slot_index]);
    auto slot_size = GetSlotSize(buffer_opts.DataSize);

    chunk.UserVA = slot_va;
    chunk.UserSize = slot_size;
    if (!chunk.MapToSystem(m_pep))
      continue;
    m_chunks.emplace_back(std::move(chunk));
  }
  for (auto slot_index = buffer_opts.Slots; slot_index < buffer_opts.Slots + ringbuffer_opts.Slots; ++slot_index) {
    auto slot_va = reinterpret_cast<uint64_t>(shmem->slots_memory[slot_index]);
    auto slot_size = GetSlotSize(ringbuffer_opts.DataSize);

    chunk.UserVA = slot_va;
    chunk.UserSize = slot_size;
    if (!chunk.MapToSystem(m_pep))
      continue;
    m_chunks.emplace_back(std::move(chunk));
  }

  m_rcu_buffer = buffer_opts;
  m_rcu_ringbuffer = ringbuffer_opts;

  return true;
}

bool KernelSharedMemory::ProcessEvents(long long int wait_time) {
  if (m_chunks.size() < 1)
    return false;

  auto shmem = m_chunks[0].Get<struct shmem>();
  if (!shmem)
    return false;

  {
    auto user_wants_shutdown = InterlockedCompareExchange(&shmem->user_wants_shutdown, 0, 0);
    if (user_wants_shutdown != 0) {
      ShutdownImmediately();
      return false;
    }
  }

  if (wait_time < 0LL) {
    LARGE_INTEGER wait = {.QuadPart = wait_time};
    KeDelayExecutionThread(KernelMode, FALSE, &wait);

    auto user_wants_shutdown = InterlockedCompareExchange(&shmem->user_wants_shutdown, 0, 0);
    if (user_wants_shutdown != 0) {
      ShutdownImmediately();
      return false;
    }
  } else if (wait_time > 0LL) {
    KeStallExecutionProcessor(wait_time);
  } else {
    ZwYieldExecution();
  }

  return true;
}

bool KernelSharedMemory::ShutdownImmediately() {
  if (!m_pep || !m_obj || m_chunks.size() < 1)
    return false;

  auto shmem = m_chunks[0].Get<struct shmem>();
  if (!shmem)
    return false;
  InterlockedExchange(&shmem->opened_by_kernel, 0);
  m_chunks.clear();

  ::CloseProcess(&m_pep, &m_obj);
  m_pep = nullptr;
  m_obj = nullptr;

  return true;
}

void* KernelSharedMemory::GetByUserVA(void* user_va) {
  if (m_chunks.size() < 1)
    return nullptr;
  const auto & found = eastl::find_if(m_chunks.cbegin() + 1, m_chunks.cend(), [user_va](const auto & item) {
    return reinterpret_cast<uint64_t>(user_va) == item.UserVA;
  });
  if (found == m_chunks.cend())
    return nullptr;
  return found->Memory;
}

bool KernelSharedMemory::ReadBufferData(const DataReadCallback & read_callback) {
  auto shmem = m_chunks[0].Get<struct shmem>();
  if (!shmem)
    return false;

  uint64_t retries = 0;
  for (;;) {
    const auto active = InterlockedCompareExchange64(&shmem->rcu_buffer.active, 0, 0);
    auto slot = Get<struct rcu_slot>(shmem->slots_memory[active]);
    if (!slot)
      return false;

    long long int gen_before = InterlockedCompareExchange64(&slot->generation, 0, 0);
    KeMemoryBarrier();
    ::memcpy(m_read_buffer, &slot->data[0], m_rcu_buffer.DataSize);
    KeMemoryBarrier();
    long long int gen_after = InterlockedCompareExchange64(&slot->generation, 0, 0);

    if (gen_before == gen_after && (gen_before & 1) == 0) {
      read_callback(m_read_buffer, retries);
      return true;
    }

    YieldProcessor();
    retries++;
  }

  return true;
}

bool KernelSharedMemory::WriteBufferData(const DataWriteCallback & write_callback) {
  auto shmem = m_chunks[0].Get<struct shmem>();
  if (!shmem)
    return false;

  const auto active = InterlockedCompareExchange64(&shmem->rcu_buffer.active, 0, 0);
  const auto next = (active + 1) % m_rcu_buffer.Slots;
  auto slot = Get<struct rcu_slot>(shmem->slots_memory[next]);
  if (!slot)
    return false;

  InterlockedIncrement64(&slot->generation);
  KeMemoryBarrier();
  write_callback(&slot->data[0]);
  KeMemoryBarrier();
  InterlockedIncrement64(&slot->generation);

  InterlockedExchange64(&shmem->rcu_buffer.active, next);

  return true;
}

bool KernelSharedMemory::WriteRingbufferData(const DataWriteCallback & write_callback) {
  auto shmem = m_chunks[0].Get<struct shmem>();
  if (!shmem)
    return false;

  const auto write_index = InterlockedCompareExchange64(&shmem->rcu_ring.write_index, 0, 0);
  const auto real_index = m_rcu_buffer.Slots + (write_index % m_rcu_ringbuffer.Slots);
  auto slot = Get<struct rcu_slot>(shmem->slots_memory[real_index]);
  if (!slot)
    return false;

  InterlockedIncrement64(&slot->generation);
  KeMemoryBarrier();
  write_callback(&slot->data[0]);
  KeMemoryBarrier();
  InterlockedIncrement64(&slot->generation);

  InterlockedIncrement64(&shmem->rcu_ring.write_index);

  return true;
}
#endif // BUILD_USERMODE

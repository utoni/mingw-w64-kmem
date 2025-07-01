#ifndef MEMORY_H
#define MEMORY_H 1

#include <EASTL/array.h>
#include <EASTL/initializer_list.h>
#include <EASTL/string.h>
#include <EASTL/vector.h>
#include <cstdint>
#include <cstdlib>
#include <ntifs.h>
#include <wdm.h>

#include "stringify.hpp"

struct Process {
  uint32_t NumberOfThreads;
  eastl::wstring ProcessName;
  uint64_t UniqueProcessId;
  uint32_t HandleCount;
};

struct Module {
  uint64_t DllBase;
  uint64_t EntryPoint;
  uint32_t SizeOfImage;
  eastl::wstring FullDllName;
  eastl::wstring BaseDllName;
  uint32_t Flags;
  uint16_t LoadCount;
  uint16_t TlsIndex;
};

struct Page {
  eastl::string toString() const {
    return ::toString(BaseAddress, RegionSize, Type, State, Protect);
  }

  uint64_t BaseAddress;
  uint64_t AllocationBase;
  uint32_t AllocationProtect;
  size_t RegionSize;
  uint32_t State;
  uint32_t Protect;
  uint32_t Type;
};

void SetLdrInitWaitPrefs(int waitCount, LONGLONG waitTimeout);
eastl::vector<Process> GetProcesses();
NTSTATUS OpenProcess(_In_ HANDLE pid, _Out_ PEPROCESS *pep,
                     _Out_ HANDLE *process);
NTSTATUS CloseProcess(_In_ _Out_ PEPROCESS *pep, _In_ _Out_ HANDLE *process);
eastl::vector<Page> GetPages(_In_ HANDLE obj, SIZE_T maxPages = 1024,
                             ULONG_PTR startAddress = 0);
eastl::vector<Module> GetModules(_In_ PEPROCESS Process, _In_ BOOLEAN isWow64);
NTSTATUS ProtectVirtualMemory(_In_ PEPROCESS pep, _In_ uint64_t addr,
                              _In_ SIZE_T size, _In_ ULONG newProt,
                              _Out_ ULONG *oldProt);
NTSTATUS RestoreProtectVirtualMemory(_In_ PEPROCESS pep, _In_ uint64_t addr,
                                     _In_ SIZE_T siz, _In_ ULONG old_prot);
NTSTATUS ReadVirtualMemory(_In_ PEPROCESS pep, _In_ uint64_t sourceAddress,
                           _Out_ UCHAR *targetAddress, _In_ _Out_ SIZE_T *size);
NTSTATUS WriteVirtualMemory(_In_ PEPROCESS pep, _In_ const UCHAR *sourceAddress,
                            _Out_ uint64_t targetAddress,
                            _In_ _Out_ SIZE_T *size);

#ifdef ENABLE_EXPERIMENTAL
namespace Experimental {
/*
 * Copy Pasta from:
 * https://www.unknowncheats.me/forum/anti-cheat-bypass/594858-updated-physical-mem-attach-paste-ready.html
 */
static constexpr uint8_t page_offset_size = 12;
static constexpr uint64_t page_mask = (~0xfull << 8) & 0xfffffffffull;

uint64_t GetProcessCr3(_In_ const PEPROCESS pe_process);
PEPROCESS SwapProcess(_In_ PEPROCESS new_process);

uint64_t GetUserDirectoryTableBaseOffset();
NTSTATUS ReadPhysicalAddress(_In_ PVOID TargetAddress, _In_ PVOID lpBuffer,
                             _In_ SIZE_T Size, _Out_ SIZE_T *BytesRead);
NTSTATUS WritePhysicalAddress(_In_ PVOID TargetAddress, _In_ PVOID lpBuffer,
                              _In_ SIZE_T Size, _Out_ SIZE_T *BytesWritten);
uint64_t GetKernelDirBase();
uint64_t TranslateLinearAddress(_In_ uint64_t directoryTableBase,
                                _In_ uint64_t virtualAddress);
NTSTATUS WriteProcessMemory(_In_ HANDLE pid, _In_ uint64_t Address,
                            _In_ uint64_t AllocatedBuffer, _In_ SIZE_T size,
                            _Out_ SIZE_T *written);
NTSTATUS ReadProcessMemory(_In_ HANDLE pid, _In_ uint64_t Address,
                           _In_ uint64_t AllocatedBuffer, _In_ SIZE_T size,
                           _Out_ SIZE_T *read);
uint64_t VirtualAddressToPhysicalAddress(_In_ PVOID VirtualAddress);
uint64_t PhysicalAddressToVirtualAddress(_In_ uint64_t PhysicalAddress);
}; // namespace Experimental
#endif

class Memory {
public:
  Memory(_In_ PEPROCESS &pep) : m_pep(pep) { ClearLastErrorAndSize(); }
  Memory(const Memory &) = delete;

  void ClearLastErrorAndSize() {
    m_last_error = STATUS_SUCCESS;
    m_last_size = 0;
  }

  static bool IsValidAddress(uint64_t address) {
    return address >= 0x10000 && address < 0x000F000000000000;
  }

  template <typename T> T Read(uint64_t sourceAddress) {
    if (!IsValidAddress(sourceAddress))
      return T();
    T value;
    SIZE_T size = sizeof(value);
    m_last_error = ReadVirtualMemory(m_pep, sourceAddress,
                                     reinterpret_cast<UCHAR *>(&value), &size);
    m_last_size = size;
    if (m_last_error == STATUS_SUCCESS && m_last_size == sizeof(T))
      return value;
    return T();
  }

  template <typename T>
  T ReadChain(uint64_t sourceAddress,
              const eastl::vector<uint64_t> &chainedOffsets) {
    for (const auto &offset : chainedOffsets) {
      if (offset == chainedOffsets.back())
        break;
      sourceAddress = Read<uint64_t>(sourceAddress + offset);
      if (!sourceAddress)
        break;
    }
    if (chainedOffsets.size() == 0)
      return Read<T>(sourceAddress);
    else
      return Read<T>(sourceAddress + chainedOffsets.back());
  }

  template <typename T, size_t N>
  bool ReadBuffer(uint64_t sourceAddress, T out[N]) {
    if (!IsValidAddress(sourceAddress))
      return false;
    SIZE_T size = sizeof(T) * N;
    m_last_error = ReadVirtualMemory(m_pep, sourceAddress,
                                     reinterpret_cast<UCHAR *>(out), &size);
    m_last_size = size;
    return Succeeded<T, N>();
  }

  template <size_t N> bool ReadString(uint64_t sourceAddress, char out[N]) {
    const auto retval = ReadBuffer<char, N - 1>(sourceAddress, out);
    out[m_last_size] = '\0';
    return retval;
  }

  template <typename T> bool Write(uint64_t targetAddress, const T &writeData) {
    if (!IsValidAddress(targetAddress))
      return false;
    SIZE_T size = sizeof(T);
    m_last_error =
        WriteVirtualMemory(m_pep, reinterpret_cast<const UCHAR *>(&writeData),
                           targetAddress, &size);
    m_last_size = size;
    return Succeeded<T, 1>();
  }

  template <typename T, size_t N> bool Succeeded() {
    return m_last_error == STATUS_SUCCESS && m_last_size == sizeof(T) * N;
  }

  NTSTATUS LastError() { return m_last_error; }
  SIZE_T LastSize() { return m_last_size; }

private:
  PEPROCESS &m_pep;
  NTSTATUS m_last_error;
  SIZE_T m_last_size;
};

namespace PatternScanner {
bool SearchWithMask(const uint8_t *buffer, size_t buffer_size,
                    const uint8_t *pattern, size_t pattern_size,
                    const eastl::string_view &mask,
                    eastl::vector<size_t> &results);

template <size_t PM, size_t N>
SearchWithMask(const eastl::array<uint8_t, N> &buffer,
               const eastl::array<uint8_t, PM> &pattern,
               const eastl::string_view &mask, eastl::vector<size_t> &results) {
  return SearchWithMask(buffer.data(), eastl::size(buffer), pattern.data(),
                        eastl::size(pattern), mask, results);
}

template <size_t N>
SearchWithMask(const eastl::array<uint8_t, N> &buffer,
               const std::initializer_list<uint8_t> &pattern,
               const eastl::string_view &mask, eastl::vector<size_t> &results) {
  return SearchWithMask(buffer.data(), eastl::size(buffer), pattern.begin(),
                        eastl::size(pattern), mask, results);
}

class ProcessModule {
public:
  ProcessModule(_In_ PEPROCESS pep, _In_ HANDLE obj,
                const std::initializer_list<uint8_t> &pattern,
                const eastl::string_view &mask)
      : m_max_pages(8192), m_pep(pep), m_obj(obj), m_pattern(pattern),
        m_mask(mask), m_offset(0) {}
  ProcessModule(_In_ PEPROCESS pep, _In_ HANDLE obj,
                const std::initializer_list<uint8_t> &pattern, const char *mask)
      : m_max_pages(8192), m_pep(pep), m_obj(obj), m_pattern(pattern),
        m_mask(mask), m_offset(0) {}
  ProcessModule(const ProcessModule &) = delete;

  void SetMaxPages(SIZE_T new_max_pages) { m_max_pages = new_max_pages; }
  bool Scan(const eastl::wstring_view &module_name,
            eastl::vector<size_t> &results, size_t max_results = 128);
  bool Scan(const wchar_t *module_name, eastl::vector<size_t> &results,
            size_t max_results = 128) {
    return Scan(eastl::wstring_view(module_name), results, max_results);
  }

private:
  SIZE_T m_max_pages;
  PEPROCESS m_pep;
  HANDLE m_obj;
  const std::initializer_list<uint8_t> &m_pattern;
  const eastl::string_view m_mask;
  size_t m_offset;
};
} // namespace PatternScanner
#endif

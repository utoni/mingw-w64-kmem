#ifndef MEMORY_H
#define MEMORY_H 1

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

eastl::vector<Process> GetProcesses();
NTSTATUS OpenProcess(_In_ HANDLE pid, _Out_ PEPROCESS *pep, _Out_ HANDLE *process);
NTSTATUS CloseProcess(_In_ _Out_ PEPROCESS *pep, _In_ _Out_ HANDLE *process);
eastl::vector<Page> GetPages(_In_ HANDLE obj, SIZE_T maxPages = 1024,
                             ULONG_PTR startAddress = 0);
eastl::vector<Module> GetModules(_In_ PEPROCESS Process, _In_ BOOLEAN isWow64);
NTSTATUS ProtectVirtualMemory(_In_ PEPROCESS pep,
                              _In_ uint64_t addr,
                              _In_ SIZE_T size, _In_ ULONG newProt,
                              _Out_ ULONG *oldProt);
NTSTATUS RestoreProtectVirtualMemory(_In_ PEPROCESS pep, _In_ uint64_t addr,
                                     _In_ SIZE_T siz, _In_ ULONG old_prot);
NTSTATUS ReadVirtualMemory(_In_ PEPROCESS pep, _In_ uint64_t sourceAddress,
                           _Out_ UCHAR *targetAddress, _In_ _Out_ SIZE_T *size);
NTSTATUS WriteVirtualMemory(_In_ PEPROCESS pep, _In_ UCHAR *sourceAddress,
                            _Out_ uint64_t targetAddress,
                            _In_ _Out_ SIZE_T *size);

#endif

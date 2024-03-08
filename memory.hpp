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

void SetLdrInitWaitPrefs(int waitCount, LONGLONG waitTimeout);
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
NTSTATUS WriteVirtualMemory(_In_ PEPROCESS pep, _In_ const UCHAR *sourceAddress,
                            _Out_ uint64_t targetAddress,
                            _In_ _Out_ SIZE_T *size);

class Memory {
public:
    Memory(_In_ PEPROCESS& pep) : m_pep(pep) {
        ClearLastErrorAndSize();
    }
    Memory(const Memory&) = delete;

    void ClearLastErrorAndSize() {
        m_last_error = STATUS_SUCCESS;
        m_last_size = 0;
    }

    static bool IsValidAddress(uint64_t address) {
        return address >= 0x10000 && address < 0x000F000000000000;
    }

    template<typename T>
    T Read(uint64_t sourceAddress) {
        if (!IsValidAddress(sourceAddress))
            return T();
        T value;
        SIZE_T size = sizeof(value);
        m_last_error = ReadVirtualMemory(m_pep, sourceAddress, reinterpret_cast<UCHAR*>(&value), &size);
        m_last_size = size;
        if (m_last_error == STATUS_SUCCESS && m_last_size == sizeof(T))
            return value;
        return T();
    }

    template<typename T>
    bool Write(uint64_t targetAddress, const T& writeData) {
        if (!IsValidAddress(targetAddress))
            return false;
        SIZE_T size = sizeof(T);
        m_last_error = WriteVirtualMemory(m_pep, reinterpret_cast<const UCHAR*>(&writeData), targetAddress, &size);
        m_last_size = size;
        if (m_last_error == STATUS_SUCCESS && m_last_size == sizeof(T))
            return true;
        return false;
    }

    NTSTATUS LastError() { return m_last_error; }
    SIZE_T LastSize() { return m_last_size; }

private:
    PEPROCESS& m_pep;
    NTSTATUS m_last_error;
    SIZE_T m_last_size;
};
#endif

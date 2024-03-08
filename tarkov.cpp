#include <ntddk.h>

#include <DriverThread.hpp>

#include "memory.hpp"

using namespace DriverThread;

static Thread thread;

static uint64_t SearchTarkovProcess(void) {
  const auto &procs = ::GetProcesses();
  const wchar_t targetProcess[] = L"EscapeFromTarkov.exe";
  const auto &found = eastl::find_if(procs.begin(), procs.end(),
                                     [&targetProcess](const auto &item) {
                                       if (item.ProcessName == targetProcess)
                                         return true;
                                       return false;
                                     });

  if (found == procs.end()) {
    return 0;
  }

  return found->UniqueProcessId;
}

extern "C" {
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT *DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  auto args = eastl::make_shared<ThreadArgs>();
  thread.Start(
      [](eastl::shared_ptr<ThreadArgs> args) {
        UNREFERENCED_PARAMETER(args);

        auto pid = reinterpret_cast<HANDLE>(SearchTarkovProcess());
        if (pid == NULL) {
          return STATUS_SUCCESS;
        }
        DbgPrint("Process pid: %p\n", pid);

        PEPROCESS pep;
        HANDLE obj;
        if (!NT_SUCCESS(::OpenProcess(pid, &pep, &obj))) {
            return STATUS_SUCCESS;
        }

        // TODO: Fill me with useful code.. ;)

        return STATUS_SUCCESS;
      },
      args);

  return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ struct _DRIVER_OBJECT *DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  DbgPrint("%s\n", "Waiting for thread termination..");
  thread.WaitForTermination();
}
}

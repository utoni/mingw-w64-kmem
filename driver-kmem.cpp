#include <ntddk.h>

#include <DriverThread.hpp>

#include "memory.hpp"

using namespace DriverThread;

static Thread thread;

extern "C" {
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT *DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  DbgPrint("%s\n", "Starting thread..");
  auto args = eastl::make_shared<ThreadArgs>();
  thread.Start(
      [](eastl::shared_ptr<ThreadArgs> args) {
        UNREFERENCED_PARAMETER(args);

        const auto &procs = ::GetProcesses();
        DbgPrint("Got %zu processes on this machine\n", procs.size());
        const wchar_t targetProcess[] = L"explorer.exe";
        const auto &found = eastl::find_if(
            procs.begin(), procs.end(), [&targetProcess](const auto &item) {
              if (item.ProcessName == targetProcess)
                return true;
              return false;
            });
        if (found == procs.end()) {
          DbgPrint("Process not found: '%ws'\n", targetProcess);
          return STATUS_SUCCESS;
        }
        DbgPrint("Process '%ws' pid: %zu\n", targetProcess,
                 found->UniqueProcessId);

        auto pid = reinterpret_cast<HANDLE>(found->UniqueProcessId);
        PEPROCESS pep;
        HANDLE obj;
        if (NT_SUCCESS(::OpenProcess(pid, &pep, &obj))) {
          DbgPrint("Opened process with pid 0x%X\n", pid);
          const auto &mods = ::GetModules(pep, FALSE);
          DbgPrint("Got %zu modules\n", mods.size());
          for (const auto &mod : mods) {
            DbgPrint("Module: '%ws'\n", mod.BaseDllName.c_str());
          }

          const auto &pages = ::GetPages(obj, 64);
          DbgPrint("Got %zu pages\n", pages.size());
          for (const auto &page : pages) {
            DbgPrint("%s\n", page.toString().c_str());
          }

          ::CloseProcess(&pep, &obj);
        }

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

#include <ntddk.h>

#include <DriverThread.hpp>
#include <except.h>
#include <obfuscate.hpp>

#include "memory.hpp"

using namespace DriverThread;

static Thread thread;
static Event shutdown_event;
static auto targetProcess = skCrypt(L"bf4.exe");

static uint64_t SearchBF4Process(void) {
  const auto &procs = ::GetProcesses();
  const auto &found =
      eastl::find_if(procs.begin(), procs.end(), [](const auto &item) {
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

int mainloop_exception_handler(_In_ EXCEPTION_POINTERS *lpEP) {
  (void)lpEP;
  return EXCEPTION_EXECUTE_HANDLER;
}

int unload_exception_handler(_In_ EXCEPTION_POINTERS *lpEP) {
  (void)lpEP;
  return EXCEPTION_EXECUTE_HANDLER;
}

NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT *DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  auto args = eastl::make_shared<ThreadArgs>();
  thread.Start(
      [](eastl::shared_ptr<ThreadArgs> args) {
        UNREFERENCED_PARAMETER(args);

        HANDLE bf4_pid = NULL;
        PEPROCESS pep = NULL;
        HANDLE obj = NULL;
        uint64_t base = 0;
        LONGLONG wait_timeout = (-1LL) * 10LL * 1000LL * 250LL;

        DbgPrint("%s\n", "start");
        __dpptry(mainloop_exception_handler, mainloop_seh) {
          while (shutdown_event.Wait(wait_timeout) == STATUS_TIMEOUT) {
            if (!bf4_pid) {
              wait_timeout = (-1LL) * 10LL * 1000LL * 250LL;
              bf4_pid = reinterpret_cast<HANDLE>(SearchBF4Process());
              if (bf4_pid == NULL) {
                continue;
              }
              DbgPrint("pid: %p\n", bf4_pid);

              if (!NT_SUCCESS(::OpenProcess(bf4_pid, &pep, &obj))) {
                bf4_pid = NULL;
                continue;
              }

              base = 0;
              while (!base) {
                LARGE_INTEGER wait = {.QuadPart =
                                          (-1LL) * 10LL * 1000LL * 250LL};
                KeDelayExecutionThread(KernelMode, TRUE, &wait);

                const auto mods = ::GetModules(pep, FALSE);
                DbgPrint("mods: %zu\n", mods.size());
                for (const auto &mod : mods) {
                  if (mod.BaseDllName == targetProcess) {
                    DbgPrint("%s\n", "found");
                    base = mod.DllBase;
                    break;
                  }
                }

                bf4_pid = reinterpret_cast<HANDLE>(SearchBF4Process());
                if (!bf4_pid)
                  break;
              }

              wait_timeout = (-1LL) * 10LL * 1000LL * 50LL;
            }

            Memory memory(pep);
            // Offsets stolen from:
            // https://github.com/ALEHACKsp/bf4-external-cheat/blob/master/Offsets.cs
            auto client_game_context = memory.Read<uint64_t>(0x142670d80);
            auto client_player_manager =
                memory.Read<uint64_t>(client_game_context + 0x60);
            auto local_player =
                memory.Read<uint64_t>(client_player_manager + 0x540);
            auto player_array =
                memory.Read<uint64_t>(client_player_manager + 0x548);

            if (!client_game_context) {
              bf4_pid = NULL;
              ::CloseProcess(&pep, &obj);
              continue;
            }
            if (!client_player_manager || !local_player || !player_array)
              continue;

            bool in_vehicle = false;
            auto local_soldier =
                memory.Read<uint64_t>(local_player + 0x14B0 - sizeof(uint64_t));
            if (!local_soldier)
              local_soldier = memory.Read<uint64_t>(local_player + 0x14D0);
            else
              in_vehicle = true;
            if (!local_soldier)
              continue;

            auto health_component =
                memory.Read<uint64_t>(local_soldier + 0x0140);
            auto health = memory.Read<float>(health_component + 0x0020);
            if (health <= 0.0f)
              continue;

            if (in_vehicle) {
              auto current_weapon_firing = memory.Read<uint64_t>(0x1423b2ec8);
              if (!current_weapon_firing)
                continue;

              auto primary_fire =
                  memory.Read<uint64_t>(current_weapon_firing + 0x0128);
              auto shot_config_data1 =
                  memory.Read<uint64_t>(primary_fire + 0x0010);

              auto vehicle_bullets_per_shell =
                  memory.Read<uint32_t>(shot_config_data1 + 0x0060 + 0x0078);
              if (vehicle_bullets_per_shell != 2)
                memory.Write<const uint32_t>(
                    shot_config_data1 + 0x0060 + 0x0078, 2);

              auto vehicle_bullets_per_shot =
                  memory.Read<uint32_t>(shot_config_data1 + 0x0060 + 0x007C);
              if (vehicle_bullets_per_shot != 2)
                memory.Write<const uint32_t>(
                    shot_config_data1 + 0x0060 + 0x007C, 2);

              continue;
            }

            auto soldier_weapon_component =
                memory.Read<uint64_t>(local_soldier + 0x0570);
            auto weapon_handle =
                memory.Read<uint64_t>(soldier_weapon_component + 0x0890);
            auto active_slot =
                memory.Read<uint32_t>(soldier_weapon_component + 0x0A98);
            auto soldier_weapon =
                memory.Read<uint64_t>(weapon_handle + active_slot * 0x8);
            auto corrected_firing =
                memory.Read<uint64_t>(soldier_weapon + 0x49C0);
            auto sway = memory.Read<uint64_t>(corrected_firing + 0x0078);
            auto sway_data = memory.Read<uint64_t>(sway + 0x0008);

            auto first_shot_recoil_multiplier =
                memory.Read<float>(sway_data + 0x444);
            if (first_shot_recoil_multiplier != 0.0f) {
              memory.Write<const float>(sway_data + 0x444, 0.0f);
              memory.Write<const float>(sway_data + 0x440, 100.0f);
            }

            auto deviation_scale_factor_zoom =
                memory.Read<float>(sway_data + 0x430);
            if (deviation_scale_factor_zoom != 0.0f) {
              memory.Write<const float>(sway_data + 0x430, 0.0f);
              memory.Write<const float>(sway_data + 0x434, 0.0f);
              memory.Write<const float>(sway_data + 0x438, 0.0f);
              memory.Write<const float>(sway_data + 0x43C, 0.0f);
            }

            auto breath_control_handler =
                memory.Read<uint64_t>(local_soldier + 0x0588);
            if (breath_control_handler)
              memory.Write<const float>(breath_control_handler + 0x0058, 0.0f);

            auto primary_fire =
                memory.Read<uint64_t>(corrected_firing + 0x0128);
            auto firing_function_data =
                memory.Read<uint64_t>(primary_fire + 0x0010);

            auto bullets_per_shell =
                memory.Read<uint32_t>(firing_function_data + 0x0060 + 0x0078);
            if (bullets_per_shell != 2)
              memory.Write<const uint32_t>(
                  firing_function_data + 0x0060 + 0x0078, 2);

            auto bullets_per_shot =
                memory.Read<uint32_t>(firing_function_data + 0x0060 + 0x007C);
            if (bullets_per_shot != 2)
              memory.Write<const uint32_t>(
                  firing_function_data + 0x0060 + 0x007C, 2);
          }
          if (bf4_pid)
            ::CloseProcess(&pep, &obj);
        }
        __dppexcept(mainloop_seh) { return STATUS_UNSUCCESSFUL; }
        __dpptryend(mainloop_seh);

        return STATUS_SUCCESS;
      },
      args);

  return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ struct _DRIVER_OBJECT *DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  DbgPrint("%s\n", "Waiting for thread termination..");
  __dpptry(unload_exception_handler, unload_seh) {
    shutdown_event.Notify();
    while (thread.WaitForTermination() != STATUS_UNSUCCESSFUL) {
    }
  }
  __dppexcept(unload_seh) {}
  __dpptryend(unload_seh);
}
}

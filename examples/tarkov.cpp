#include <ntddk.h>

#include <EASTL/algorithm.h>
#include <EASTL/array.h>
#include <EASTL/unordered_map.h>
#include <eastl_compat.hpp>
#include <DriverThread.hpp>
#include <obfuscate.hpp>

#include "memory.hpp"
#include "stringify.hpp"

using namespace DriverThread;

static Thread thread;
static Event shutdown_event;
static auto targetProcess = skCrypt(L"EscapeFromTarkov.exe");
static auto targetModule = skCrypt(L"UnityPlayer.dll");

struct BaseObject
{
    uint64_t previousObjectLink;
    uint64_t nextObjectLink;
    uint64_t object;
};

struct GameObjectManager
{
    uint64_t lastTaggedObject;
    uint64_t taggedObjects;
    uint64_t lastActiveObject;
    uint64_t activeObjects;
    uint64_t LastActiveNode;
    uint64_t ActiveNodes;
};

struct UnityList
{
    uint8_t pad[16];
    uint64_t pointer;
    uint32_t size;
};

template<size_t N>
struct UnityString
{
    uint8_t pad[16];
    uint32_t length;
    wchar_t value[N];
};

template<typename T>
struct Vector3
{
    T x;
    T y;
    T z;
};

struct Player
{
    enum Side {
        BEAR = 1, USEC = 2, SCAV = 4
    } side;
    eastl::string nickname;
    Vector3<float> position;
};

static const eastl::unordered_map<wchar_t, eastl::string> cyrillic_to_latin{
    {L'А', "A"}, {L'Б', "B"}, {L'В', "V"}, {L'Г', "G"}, {L'Д', "D"},
    {L'Е', "E"}, {L'Ё', "E"}, {L'Ж', "Zh"}, {L'З', "Z"}, {L'И', "I"},
    {L'Й', "Y"}, {L'К', "K"}, {L'Л', "L"}, {L'М', "M"}, {L'Н', "N"},
    {L'О', "O"}, {L'П', "P"}, {L'Р', "R"}, {L'С', "S"}, {L'Т', "T"},
    {L'У', "U"}, {L'Ф', "F"}, {L'Х', "Kh"}, {L'Ц', "Ts"}, {L'Ч', "Ch"},
    {L'Ш', "Sh"}, {L'Щ', "Shch"}, {L'Ъ', ""}, {L'Ы', "Y"}, {L'Ь', ""},
    {L'Э', "E"}, {L'Ю', "Yu"}, {L'Я', "Ya"},
    {L'а', "a"}, {L'б', "b"}, {L'в', "v"}, {L'г', "g"}, {L'д', "d"},
    {L'е', "e"}, {L'ё', "e"}, {L'ж', "zh"}, {L'з', "z"}, {L'и', "i"},
    {L'й', "y"}, {L'к', "k"}, {L'л', "l"}, {L'м', "m"}, {L'н', "n"},
    {L'о', "o"}, {L'п', "p"}, {L'р', "r"}, {L'с', "s"}, {L'т', "t"},
    {L'у', "u"}, {L'ф', "f"}, {L'х', "kh"}, {L'ц', "ts"}, {L'ч', "ch"},
    {L'ш', "sh"}, {L'щ', "shch"}, {L'ъ', ""}, {L'ы', "y"}, {L'ь', ""},
    {L'э', "e"}, {L'ю', "yu"}, {L'я', "ya"}
};

static eastl::string transliterate_cyrillic(wchar_t* input, size_t length)
{
  eastl::string retval;

  for (size_t i = 0; i < length; ++i) {
    const auto& got = cyrillic_to_latin.find(input[i]);
    if (got == cyrillic_to_latin.end()) {
      retval += *reinterpret_cast<char*>(&input[i]);
    } else {
      retval += got->second;
    }
  }

  return retval;
}

double square_root(const double number) {
  constexpr double ACCURACY = 0.001;
  double lower, upper, guess;

  if (number < 1) {
    lower = number;
    upper = 1;
  } else {
    lower = 1;
    upper = number;
  }

  while ((upper-lower) > ACCURACY) {
    guess = (lower + upper)/2;
    if (guess*guess > number)
      upper =guess;
    else
      lower = guess;
  }
  return (lower + upper)/2;
}

static uint64_t GetObjectFromList(Memory& memory, uint64_t listPtr, uint64_t lastObjectPtr, const char * const objectName)
{
  char name[128];
  uint64_t classNamePtr = 0x0;

  BaseObject activeObject = memory.Read<BaseObject>(listPtr);
  BaseObject lastObject = memory.Read<BaseObject>(lastObjectPtr);

  if (activeObject.object != 0x0)
  {
    while (activeObject.object != 0 && activeObject.object != lastObject.object)
    {
      classNamePtr = memory.Read<uint64_t>(activeObject.object + 0x60);
      memory.ReadBuffer<char, sizeof(name)>(classNamePtr, name);

      if (strncmp(name, objectName, sizeof(name)) == 0)
        return activeObject.object;

      activeObject = memory.Read<BaseObject>(activeObject.nextObjectLink);
    }
  }
  if (lastObject.object != 0x0)
  {
    classNamePtr = memory.Read<uint64_t>(lastObject.object + 0x60);
    memory.ReadBuffer<char, sizeof(name)>(classNamePtr, name);

    if (strncmp(name, objectName, sizeof(name)) == 0)
      return lastObject.object;
  }

  memset(name, 0, sizeof(name));

  return 0;
}

static uint64_t SearchTarkovProcess(void) {
  const auto &procs = ::GetProcesses();
  const auto &found = eastl::find_if(procs.begin(), procs.end(),
                                     [](const auto &item) {
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

        HANDLE tarkov_pid = NULL;
        PEPROCESS pep = NULL;
        HANDLE obj = NULL;
        uint64_t base = 0;
        LONGLONG wait_timeout = (-1LL) * 10LL * 1000LL * 250LL;

        DbgPrint("%s\n", "start");
        while (shutdown_event.Wait(wait_timeout) == STATUS_TIMEOUT) {
          if (!tarkov_pid) {
            wait_timeout = (-1LL) * 10LL * 1000LL * 1000LL;
            tarkov_pid = reinterpret_cast<HANDLE>(SearchTarkovProcess());
            if (tarkov_pid == NULL) {
              continue;
            }
            DbgPrint(skCrypt("pid: %p\n"), tarkov_pid);

            if (!NT_SUCCESS(::OpenProcess(tarkov_pid, &pep, &obj))) {
              tarkov_pid = NULL;
              continue;
            }

            base = 0;
            while (!base && tarkov_pid) {
              LARGE_INTEGER wait = {.QuadPart = (-1LL) * 10LL * 1000LL * 250LL};
              KeDelayExecutionThread(KernelMode, TRUE, &wait);

              const auto mods = ::GetModules(pep, FALSE);
              DbgPrint(skCrypt("mods: %zu\n"), mods.size());
              for (const auto &mod : mods) {
                if (mod.BaseDllName == targetModule) {
                  DbgPrint("%s\n", "found");
                  base = mod.DllBase;
                  break;
                }
              }

              tarkov_pid = reinterpret_cast<HANDLE>(SearchTarkovProcess());
            }

            if (!tarkov_pid) {
              LARGE_INTEGER wait = {.QuadPart = (-1LL) * 10LL * 1000LL * 5000LL};
              KeDelayExecutionThread(KernelMode, TRUE, &wait);
              ::CloseProcess(&pep, &obj);
              continue;
            }
          }

          // Offsets stolen from: https://github.com/HuiTeab/EFT-DMA-Radar-Only-Code/blob/main/Source/Misc/Offsets.cs
          Memory memory(pep);
          auto gom_ptr = memory.Read<uint64_t>(base + 0x17FFD28);
          auto gom = memory.Read<GameObjectManager>(gom_ptr);
          if (!gom_ptr) {
            LARGE_INTEGER wait = {.QuadPart = (-1LL) * 10LL * 1000LL * 5000LL};
            KeDelayExecutionThread(KernelMode, TRUE, &wait);
            ::CloseProcess(&pep, &obj);
            tarkov_pid = NULL;
            continue;
          }

          uint64_t activeNodes = memory.Read<uint64_t>(gom.ActiveNodes);
          uint64_t lastActiveNode = memory.Read<uint64_t>(gom.LastActiveNode);
          auto game_world = GetObjectFromList(memory, activeNodes, lastActiveNode, skCrypt("GameWorld"));
          auto local_game_world = memory.ReadChain<uint64_t>(game_world, { 0x30, 0x18, 0x28 });
          auto local_player = memory.Read<uint64_t>(local_game_world + 0x148);
          auto local_player_class = memory.ReadChain<uint64_t>(local_player, { 0x0, 0x0, 0x48 });
          char local_player_class_name[64] = {};
          memory.ReadString<sizeof(local_player_class_name)>(local_player_class, local_player_class_name);
          auto registered_players = memory.Read<uint64_t>(local_game_world + 0xF0);
          auto registered_players_list = memory.Read<UnityList>(registered_players);

          Player me;
          eastl::vector<Player> players;
          size_t player_count = 0, scav_count = 0;
          for (uint32_t i = 0; i < registered_players_list.size; ++i) {
            auto player_base = memory.Read<uint64_t>(registered_players_list.pointer + 0x20 + (i * 0x8));
            auto player_class = memory.ReadChain<uint64_t>(player_base, { 0x0, 0x0, 0x48 });
            char player_class_name[64] = {};
            memory.ReadString<sizeof(player_class_name)>(player_class, player_class_name);
            auto player_info = memory.ReadChain<uint64_t>(player_base, { 0x588 /* EFT Profile */,
                                                                         0x28 /* Player Info */ });
            const auto player_class_name_str = eastl::string(player_class_name);
            if (player_class_name_str == skCrypt("ObservedPlayerView")) {
                auto player_is_ai = memory.Read<unsigned char>(player_base + 0x109);
                if (!player_is_ai)
                    player_count++;
                auto player_side = memory.Read<uint32_t>(player_base + 0xF0);
                if (player_side == 4 /* scav */)
                    scav_count++;
                if (player_is_ai)
                    continue;
                auto pos = memory.ReadChain<Vector3<float>>(player_base, { 0x10, 0x30, 0x30, 0x8, 0x38, 0x90 });
                auto player_nickname = memory.Read<uint64_t>(player_base + 0x48);
                auto player_nickname_unity = memory.Read<UnityString<64>>(player_nickname);
                const auto& player_trans_nickname = transliterate_cyrillic(player_nickname_unity.value,
                                                                           player_nickname_unity.length);
                players.emplace_back(Player{ .side = static_cast<Player::Side>(player_side),
                                             .nickname = player_trans_nickname, .position = pos });
            } else if (player_class_name_str == skCrypt("ClientPlayer") ||
                       player_class_name_str == skCrypt("LocalPlayer") ||
                       player_class_name_str == skCrypt("HideoutPlayer"))
            {
                auto player_side = memory.Read<uint32_t>(player_info + 0x70);
                if (player_side == 4 /* scav */)
                    scav_count++;
                auto pos = memory.ReadChain<Vector3<float>>(player_base, { 0x10, 0x30, 0x30, 0x8, 0x38, 0x90 });
                me = Player{ .side = static_cast<Player::Side>(player_side),
                             .nickname = "", .position = pos };
            }
          }
          DbgPrint(skCrypt("Players/Scavs: %u/%u\n"), player_count, scav_count);
          for (const auto& player : players) {
            eastl::string pside;
            switch (player.side) {
              case Player::Side::BEAR:
                pside = "BEAR"; break;
              case Player::Side::USEC:
                pside = "USEC"; break;
              case Player::Side::SCAV:
                pside = "SCAV"; break;
              default:
                pside = "UNKN"; break;
            }
            auto xd = me.position.x - player.position.x;
            xd *= xd;
            auto yd = me.position.y - player.position.y;
            yd *= yd;
            auto zd = me.position.z - player.position.z;
            zd *= zd;
            auto pdist = square_root(xd + yd + zd);
            DbgPrint(skCrypt("Player %s: [%s] %s [%s %s %s]\n"), pside.c_str(), ::to_string(pdist), player.nickname,
                     ::to_string(player.position.x).c_str(), ::to_string(player.position.y).c_str(),
                     ::to_string(player.position.z).c_str());
          }

// You'll figure that out..
#if 0
          auto camera_address = memory.Read<uint64_t>(base + 0x0179F500);
          if (!camera_address)
            continue;
          auto all_cameras = memory.Read<uint64_t>(camera_address);
          if (!all_cameras)
            continue;

          uint64_t optic_camera = 0;
          for (uint64_t i = 0; i < 512; ++i) {
            auto camera = memory.Read<uint64_t>(all_cameras + i * 0x8);
            if (!camera)
              break;
            auto camera_obj = memory.Read<uint64_t>(camera + 0x30);
            if (!camera_obj)
              break;
            auto camera_name_ptr = memory.Read<uint64_t>(camera_obj + 0x60);

            char buf[64] = {};
            memory.ReadString<sizeof(buf)>(camera_name_ptr, buf);
            if (memory.LastSize() > 0 && strncmp(buf, skCrypt("BaseOpticCamera(Clone)"), sizeof(buf)) == 0)
              optic_camera = camera_name_ptr;
          }
          DbgPrint(skCrypt("Optic: %p\n"), optic_camera);
#endif
        }

        return STATUS_SUCCESS;
      },
      args);

  return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ struct _DRIVER_OBJECT *DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  DbgPrint("%s\n", "Waiting for thread termination..");
  shutdown_event.Notify();
  thread.WaitForTermination();
}
}

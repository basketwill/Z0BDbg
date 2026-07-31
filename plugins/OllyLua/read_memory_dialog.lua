local function parse_address(text)
    text = tostring(text or ""):gsub("^%s+", ""):gsub("%s+$", "")
    if text == "" then
        return nil
    end
    text = text:gsub("^0[xX]", "")
    return tonumber(text, 16) or tonumber(text, 10)
end

local function hex_dump(data, base)
    local lines = {}
    for i = 1, #data, 16 do
        local hex = {}
        local ascii = {}
        local n = math.min(16, #data - i + 1)
        for j = 0, n - 1 do
            local b = data:byte(i + j)
            hex[#hex + 1] = string.format("%02X", b)
            ascii[#ascii + 1] = (b >= 32 and b <= 126) and string.char(b) or "."
        end
        lines[#lines + 1] = string.format("%016X  %-47s  %s", base + i - 1, table.concat(hex, " "), table.concat(ascii))
    end
    return table.concat(lines, "\r\n")
end

local address_text = z0dbg.input_text("Read memory", "Address, for example 401000 or 0x401000:", "401000")
if not address_text then
    return
end

local address = parse_address(address_text)
if not address then
    z0dbg.show_text("Read memory", "Invalid address: " .. tostring(address_text))
    return
end

local size_text = z0dbg.input_text("Read memory", "Size in bytes:", "100")
if not size_text then
    return
end

local size = tonumber(size_text) or parse_address(size_text)
if not size or size <= 0 then
    z0dbg.show_text("Read memory", "Invalid size: " .. tostring(size_text))
    return
end

local data, err = z0dbg.read_memory(address, size)
if not data then
    z0dbg.show_text("Read memory", "Read failed: " .. tostring(err))
    return
end

local title = string.format("Memory %016X, %d bytes", address, #data)
z0dbg.show_text(title, hex_dump(data, address))

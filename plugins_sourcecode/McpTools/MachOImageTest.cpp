#include "../../MachOImage.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <vector>

static void put32(std::vector<unsigned char>* bytes, size_t offset, unsigned int value, bool little) {
    for (int i = 0; i < 4; ++i)
        (*bytes)[offset + i] = (unsigned char)(value >> (8 * (little ? i : 3 - i)));
}
static bool save(const wchar_t* path, const std::vector<unsigned char>& bytes) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(file, &bytes[0], (DWORD)bytes.size(), &written, NULL) && written == bytes.size();
    CloseHandle(file);
    return ok;
}
static void thin(std::vector<unsigned char>* bytes, size_t offset, unsigned int cpu) {
    (*bytes)[offset] = 0xcf; (*bytes)[offset + 1] = 0xfa;
    (*bytes)[offset + 2] = 0xed; (*bytes)[offset + 3] = 0xfe;
    put32(bytes, offset + 4, cpu, true);
    put32(bytes, offset + 8, 3, true);
    put32(bytes, offset + 12, 2, true);
    put32(bytes, offset + 16, 1, true);
    put32(bytes, offset + 20, 8, true);
    put32(bytes, offset + 32, 0x80000028, true);
    put32(bytes, offset + 36, 8, true);
}
int main() {
    wchar_t directory[MAX_PATH], path[MAX_PATH];
    assert(GetTempPathW(_countof(directory), directory) &&
        GetTempFileNameW(directory, L"mho", 0, path));
    MachOImage image;
    std::vector<unsigned char> bytes(64, 0);
    thin(&bytes, 0, 0x01000007);
    assert(save(path, bytes) && image.open(path));
    assert(!image.fat() && image.slices().size() == 1 && image.slices()[0].command_count == 1);

    bytes.assign(0x200, 0);
    thin(&bytes, 0, 0x01000007);
    put32(&bytes, 20, 152, true);
    put32(&bytes, 32, 0x19, true);
    put32(&bytes, 36, 152, true);
    memcpy(&bytes[40], "__TEXT", 6);
    put32(&bytes, 56, 0x1000, true);
    put32(&bytes, 64, 0x200, true);
    put32(&bytes, 72, 0, true);
    put32(&bytes, 80, 0x200, true);
    put32(&bytes, 96, 1, true);
    memcpy(&bytes[104], "__text", 6);
    memcpy(&bytes[120], "__TEXT", 6);
    put32(&bytes, 136, 0x1100, true);
    put32(&bytes, 144, 0x10, true);
    put32(&bytes, 152, 0x100, true);
    assert(save(path, bytes) && image.open(path));
    assert(image.slices()[0].segments.size() == 1 &&
        image.slices()[0].segments[0].name == "__TEXT" &&
        image.slices()[0].segments[0].sections.size() == 1 &&
        image.slices()[0].segments[0].sections[0].name == "__text");
    put32(&bytes, 152, 0x1000, true);
    assert(save(path, bytes) && !image.open(path));

    bytes.assign(0x300, 0);
    bytes[0] = 0xca; bytes[1] = 0xfe; bytes[2] = 0xba; bytes[3] = 0xbe;
    put32(&bytes, 4, 2, false);
    put32(&bytes, 8, 0x0100000c, false); put32(&bytes, 12, 3, false);
    put32(&bytes, 16, 0x100, false); put32(&bytes, 20, 0x100, false);
    put32(&bytes, 24, 8, false);
    put32(&bytes, 28, 0x01000007, false); put32(&bytes, 32, 3, false);
    put32(&bytes, 36, 0x200, false); put32(&bytes, 40, 0x100, false);
    put32(&bytes, 44, 8, false);
    thin(&bytes, 0x100, 0x0100000c);
    thin(&bytes, 0x200, 0x01000007);
    assert(save(path, bytes) && image.open(path));
    assert(image.fat() && image.slices().size() == 2 && image.preferred_slice() == 1);
    put32(&bytes, 40, 0x2000, false);
    assert(save(path, bytes) && !image.open(path));
    DeleteFileW(path);
    puts("PASS: Mach-O thin/Fat headers, architecture selection and bounds");
    return 0;
}

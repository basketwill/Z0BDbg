#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include "ModelJson.h"

class StaticPeImage {
    HANDLE file_, mapping_;
    const unsigned char* data_;
    size_t size_;
    const IMAGE_FILE_HEADER* file_header_;
    const IMAGE_SECTION_HEADER* sections_;
    unsigned __int64 image_base_;
    bool is64_;
    DWORD entry_rva_, header_size_;
    IMAGE_DATA_DIRECTORY directories_[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    bool contains(size_t offset, size_t length) const {
        return offset <= size_ && length <= size_ - offset;
    }
    const unsigned char* at(size_t offset, size_t length) const {
        return contains(offset, length) ? data_ + offset : NULL;
    }
    static std::string number(unsigned __int64 value) {
        char text[32]; sprintf_s(text, sizeof(text), "0x%llX", value); return text;
    }
    static void quoted(std::string* out, const std::string& value) {
        ModelJson::quote(out, value);
    }
    static std::string utf8(const wchar_t* value) {
        if (!value) return "";
        int count = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
        std::string result(count > 0 ? count : 0, '\0');
        if (count > 1) {
            WideCharToMultiByte(CP_UTF8, 0, value, -1, &result[0], count, NULL, NULL);
            result.resize(count - 1);
        }
        return result;
    }
    bool rva_offset(DWORD rva, size_t length, size_t* offset) const {
        if (rva < header_size_ && length <= header_size_ - rva && contains(rva, length)) {
            *offset = rva; return true;
        }
        for (WORD i = 0; i < file_header_->NumberOfSections; ++i) {
            const IMAGE_SECTION_HEADER& section = sections_[i];
            if (rva < section.VirtualAddress) continue;
            unsigned __int64 delta = (unsigned __int64)rva - section.VirtualAddress;
            if (delta <= section.SizeOfRawData && length <= section.SizeOfRawData - delta &&
                contains((size_t)section.PointerToRawData + (size_t)delta, length)) {
                *offset = (size_t)section.PointerToRawData + (size_t)delta;
                return true;
            }
        }
        return false;
    }
    const void* rva(unsigned __int64 address, size_t length) const {
        size_t offset = 0;
        return address && address <= 0xffffffffULL &&
            rva_offset((DWORD)address, length, &offset) ? data_ + offset : NULL;
    }
    std::string cstring(size_t offset, size_t limit = 512) const {
        if (!contains(offset, 1)) return "";
        size_t end = offset;
        while (end < size_ && end - offset < limit && data_[end]) ++end;
        return end < size_ && end - offset < limit ?
            std::string((const char*)data_ + offset, end - offset) : "";
    }
    std::string rva_string(DWORD address) const {
        size_t offset = 0;
        return rva_offset(address, 1, &offset) ? cstring(offset) : "";
    }
    static std::string section_name(const IMAGE_SECTION_HEADER& section) {
        size_t n = 0;
        while (n < IMAGE_SIZEOF_SHORT_NAME && section.Name[n]) ++n;
        return std::string((const char*)section.Name, n);
    }
    unsigned __int64 file_address(size_t offset) const {
        for (WORD i = 0; i < file_header_->NumberOfSections; ++i) {
            const IMAGE_SECTION_HEADER& section = sections_[i];
            if (offset >= section.PointerToRawData &&
                offset - section.PointerToRawData < section.SizeOfRawData)
                return image_base_ + section.VirtualAddress + offset - section.PointerToRawData;
        }
        return 0;
    }
    static bool printable(unsigned char ch) { return ch >= 0x20 && ch <= 0x7e; }
public:
    StaticPeImage() : file_(INVALID_HANDLE_VALUE), mapping_(NULL), data_(NULL), size_(0),
        file_header_(NULL), sections_(NULL), image_base_(0), is64_(false), entry_rva_(0), header_size_(0) {
        ZeroMemory(directories_, sizeof(directories_));
    }
    ~StaticPeImage() {
        if (data_) UnmapViewOfFile(data_);
        if (mapping_) CloseHandle(mapping_);
        if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
    }
    bool open(const wchar_t* path) {
        file_ = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        LARGE_INTEGER bytes;
        if (file_ == INVALID_HANDLE_VALUE || !GetFileSizeEx(file_, &bytes) ||
            bytes.QuadPart < (LONGLONG)sizeof(IMAGE_DOS_HEADER) || bytes.QuadPart > 512LL * 1024 * 1024) return false;
        size_ = (size_t)bytes.QuadPart;
        mapping_ = CreateFileMappingW(file_, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!mapping_) return false;
        data_ = (const unsigned char*)MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!data_) return false;
        const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)data_;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return false;
        size_t nt = (size_t)dos->e_lfanew;
        if (!contains(nt, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) ||
            *(const DWORD*)(data_ + nt) != IMAGE_NT_SIGNATURE) return false;
        file_header_ = (const IMAGE_FILE_HEADER*)(data_ + nt + sizeof(DWORD));
        size_t optional = nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (file_header_->SizeOfOptionalHeader < sizeof(WORD) ||
            !contains(optional, file_header_->SizeOfOptionalHeader) ||
            file_header_->NumberOfSections > 96) return false;
        const WORD magic = *(const WORD*)(data_ + optional);
        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
            file_header_->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
            is64_ = false;
            const IMAGE_OPTIONAL_HEADER32* opt = (const IMAGE_OPTIONAL_HEADER32*)(data_ + optional);
            image_base_ = opt->ImageBase; entry_rva_ = opt->AddressOfEntryPoint;
            header_size_ = opt->SizeOfHeaders;
            memcpy(directories_, opt->DataDirectory, sizeof(directories_));
        } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
            file_header_->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
            is64_ = true;
            const IMAGE_OPTIONAL_HEADER64* opt = (const IMAGE_OPTIONAL_HEADER64*)(data_ + optional);
            image_base_ = opt->ImageBase; entry_rva_ = opt->AddressOfEntryPoint;
            header_size_ = opt->SizeOfHeaders;
            memcpy(directories_, opt->DataDirectory, sizeof(directories_));
        } else return false;
        size_t section_offset = optional + file_header_->SizeOfOptionalHeader;
        if (!contains(section_offset, (size_t)file_header_->NumberOfSections * sizeof(IMAGE_SECTION_HEADER))) return false;
        sections_ = (const IMAGE_SECTION_HEADER*)(data_ + section_offset);
        return true;
    }
    bool is64() const { return is64_; }
    unsigned __int64 image_base() const { return image_base_; }
    bool pdb_identity(GUID* guid, DWORD* age) const {
        if (!guid || !age || !sections_) return false;
        const IMAGE_DATA_DIRECTORY& directory = directories_[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY)) return false;
        size_t offset = 0;
        if (!rva_offset(directory.VirtualAddress, directory.Size, &offset)) return false;
        const IMAGE_DEBUG_DIRECTORY* entries =
            (const IMAGE_DEBUG_DIRECTORY*)(data_ + offset);
        size_t count = directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (size_t i = 0; i < count; ++i) {
            const IMAGE_DEBUG_DIRECTORY& entry = entries[i];
            if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData < 25) continue;
            const unsigned char* cv = entry.PointerToRawData ?
                at(entry.PointerToRawData, entry.SizeOfData) : NULL;
            if (!cv && rva_offset(entry.AddressOfRawData, entry.SizeOfData, &offset))
                cv = data_ + offset;
            if (cv && memcmp(cv, "RSDS", 4) == 0 && cv[24]) {
                memcpy(guid, cv + 4, sizeof(*guid));
                memcpy(age, cv + 20, sizeof(*age));
                return true;
            }
        }
        return false;
    }
    size_t read(unsigned __int64 address, unsigned char* output, size_t capacity) const {
        if (!output || !capacity || address < image_base_ ||
            address - image_base_ > 0xffffffffULL) return 0;
        size_t offset = 0;
        for (size_t length = capacity; length; --length) {
            if (!rva_offset((DWORD)(address - image_base_), length, &offset)) continue;
            memcpy(output, data_ + offset, length);
            return length;
        }
        return 0;
    }
    std::string info(const wchar_t* path) const {
        std::string out = "{\"ok\":true,\"path\":"; quoted(&out, utf8(path));
        out += ",\"file_size\":" + std::to_string((unsigned long long)size_);
        out += ",\"machine\":"; quoted(&out, number(file_header_->Machine));
        out += ",\"bits\":" + std::string(is64() ? "64" : "32");
        out += ",\"image_base\":"; quoted(&out, number(image_base_));
        out += ",\"entry_point\":"; quoted(&out, number(image_base_ + entry_rva_));
        out += ",\"entry_rva\":"; quoted(&out, number(entry_rva_));
        out += ",\"section_count\":" + std::to_string((unsigned long long)file_header_->NumberOfSections);
        out += ",\"timestamp\":" + std::to_string((unsigned long long)file_header_->TimeDateStamp) + "}";
        return out;
    }
    std::string sections() const {
        std::string out = "{\"ok\":true,\"sections\":[";
        for (WORD i = 0; i < file_header_->NumberOfSections; ++i) {
            if (i) out += ',';
            const IMAGE_SECTION_HEADER& section = sections_[i];
            out += "{\"name\":"; quoted(&out, section_name(section));
            out += ",\"address\":"; quoted(&out, number(image_base_ + section.VirtualAddress));
            out += ",\"rva\":"; quoted(&out, number(section.VirtualAddress));
            out += ",\"virtual_size\":" + std::to_string((unsigned long long)section.Misc.VirtualSize);
            out += ",\"file_offset\":" + std::to_string((unsigned long long)section.PointerToRawData);
            out += ",\"raw_size\":" + std::to_string((unsigned long long)section.SizeOfRawData);
            out += ",\"characteristics\":"; quoted(&out, number(section.Characteristics)); out += '}';
        }
        return out + "]}";
    }
    std::string bytes(unsigned __int64 address, size_t length) const {
        if (address < image_base_ || address - image_base_ > 0xffffffffULL || !length || length > 4096)
            return "{\"ok\":false,\"error\":\"Invalid address or size\"}";
        size_t offset = 0;
        if (!rva_offset((DWORD)(address - image_base_), length, &offset))
            return "{\"ok\":false,\"error\":\"Address is not backed by file bytes\"}";
        static const char digits[] = "0123456789ABCDEF";
        std::string hex; hex.reserve(length * 2);
        for (size_t i = 0; i < length; ++i) {
            unsigned char byte = data_[offset + i];
            hex += digits[byte >> 4]; hex += digits[byte & 15];
        }
        std::string out = "{\"ok\":true,\"address\":"; quoted(&out, number(address));
        out += ",\"file_offset\":" + std::to_string((unsigned long long)offset) + ",\"hex\":";
        quoted(&out, hex); return out + '}';
    }
    std::string imports(size_t skip, size_t limit) const {
        std::string out = "{\"ok\":true,\"imports\":[";
        size_t seen = 0, emitted = 0;
        DWORD directory = directories_[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD directory_size = directories_[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        for (DWORD i = 0; directory && i < 4096 &&
            (unsigned __int64)i * sizeof(IMAGE_IMPORT_DESCRIPTOR) < directory_size &&
            seen <= skip + limit; ++i) {
            const IMAGE_IMPORT_DESCRIPTOR* descriptor = (const IMAGE_IMPORT_DESCRIPTOR*)
                rva((unsigned __int64)directory + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (!descriptor || (!descriptor->Name && !descriptor->FirstThunk)) break;
            std::string module = rva_string(descriptor->Name);
            DWORD thunk = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
            for (DWORD j = 0; thunk && j < 65536 && seen <= skip + limit; ++j) {
                unsigned __int64 value = 0;
                if (is64()) {
                    const ULONGLONG* item = (const ULONGLONG*)rva((unsigned __int64)thunk + j * 8, sizeof(ULONGLONG));
                    if (!item) break;
                    value = *item;
                } else {
                    const DWORD* item = (const DWORD*)rva((unsigned __int64)thunk + j * 4, sizeof(DWORD));
                    if (!item) break;
                    value = *item;
                }
                if (!value) break;
                if (seen++ < skip || emitted >= limit) continue;
                if (emitted++) out += ',';
                out += "{\"module\":"; quoted(&out, module);
                out += ",\"iat_address\":"; quoted(&out, number(image_base_ + descriptor->FirstThunk + j * (is64() ? 8 : 4)));
                if (value & (is64() ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32)) {
                    out += ",\"ordinal\":" + std::to_string((unsigned long long)(value & 0xffff));
                } else {
                    DWORD name_rva = (DWORD)value;
                    out += ",\"name\":";
                    quoted(&out, name_rva <= 0xfffffffdU ? rva_string(name_rva + 2) : "");
                }
                out += '}';
            }
        }
        return out + "],\"next_offset\":" + std::to_string((unsigned long long)(skip + emitted)) +
            ",\"has_more\":" + (seen > skip + emitted ? "true}" : "false}");
    }
    bool find_import(const std::string& name, DWORD* iat_rva) const {
        if (!iat_rva || name.empty()) return false;
        DWORD directory = directories_[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD directory_size = directories_[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        for (DWORD i = 0; directory && i < 4096 &&
            (unsigned __int64)i * sizeof(IMAGE_IMPORT_DESCRIPTOR) < directory_size; ++i) {
            const IMAGE_IMPORT_DESCRIPTOR* descriptor = (const IMAGE_IMPORT_DESCRIPTOR*)
                rva((unsigned __int64)directory + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (!descriptor || (!descriptor->Name && !descriptor->FirstThunk)) break;
            DWORD thunk = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
            for (DWORD j = 0; thunk && j < 65536; ++j) {
                unsigned __int64 value = 0;
                if (is64()) {
                    const ULONGLONG* item = (const ULONGLONG*)rva((unsigned __int64)thunk + j * 8, sizeof(ULONGLONG));
                    if (!item) break;
                    value = *item;
                } else {
                    const DWORD* item = (const DWORD*)rva((unsigned __int64)thunk + j * 4, sizeof(DWORD));
                    if (!item) break;
                    value = *item;
                }
                if (!value) break;
                if (value & (is64() ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32)) continue;
                DWORD name_rva = (DWORD)value;
                if (name_rva > 0xfffffffdU || rva_string(name_rva + 2) != name) continue;
                unsigned __int64 slot = (unsigned __int64)descriptor->FirstThunk + j * (is64() ? 8 : 4);
                if (slot > 0xffffffffULL) return false;
                *iat_rva = (DWORD)slot;
                return true;
            }
        }
        return false;
    }
    std::string exports(size_t skip, size_t limit) const {
        std::string out = "{\"ok\":true,\"exports\":[";
        const IMAGE_EXPORT_DIRECTORY* directory = (const IMAGE_EXPORT_DIRECTORY*)
            rva(directories_[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));
        size_t emitted = 0, seen = 0;
        if (directory && directory->NumberOfFunctions < 65536 && directory->NumberOfNames < 65536) {
            for (DWORD i = 0; i < directory->NumberOfNames; ++i) {
                const DWORD* name_rva = (const DWORD*)rva((unsigned __int64)directory->AddressOfNames + i * 4, sizeof(DWORD));
                const WORD* ordinal_index = (const WORD*)rva((unsigned __int64)directory->AddressOfNameOrdinals + i * 2, sizeof(WORD));
                if (!name_rva || !ordinal_index || *ordinal_index >= directory->NumberOfFunctions) break;
                const DWORD* function_rva = (const DWORD*)rva((unsigned __int64)directory->AddressOfFunctions + *ordinal_index * 4, sizeof(DWORD));
                if (!function_rva) break;
                if (seen++ < skip || emitted >= limit) continue;
                if (emitted++) out += ',';
                out += "{\"name\":"; quoted(&out, rva_string(*name_rva));
                out += ",\"ordinal\":" + std::to_string((unsigned long long)(directory->Base + *ordinal_index));
                out += ",\"address\":"; quoted(&out, number(image_base_ + *function_rva));
                if (*function_rva >= directories_[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
                    (unsigned __int64)*function_rva <
                    (unsigned __int64)directories_[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress +
                    directories_[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                    out += ",\"forwarder\":"; quoted(&out, rva_string(*function_rva));
                }
                out += '}';
            }
        }
        return out + "],\"next_offset\":" + std::to_string((unsigned long long)(skip + emitted)) +
            ",\"has_more\":" + (seen > skip + emitted ? "true}" : "false}");
    }
    bool find_export(const std::string& name, DWORD* function_rva, std::string* forwarder) const {
        if (!function_rva || !forwarder || name.empty()) return false;
        const IMAGE_DATA_DIRECTORY& export_data = directories_[IMAGE_DIRECTORY_ENTRY_EXPORT];
        const IMAGE_EXPORT_DIRECTORY* directory = (const IMAGE_EXPORT_DIRECTORY*)
            rva(export_data.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));
        if (!directory || directory->NumberOfFunctions > 65536 || directory->NumberOfNames > 65536)
            return false;
        for (DWORD i = 0; i < directory->NumberOfNames; ++i) {
            const DWORD* name_rva = (const DWORD*)rva((unsigned __int64)directory->AddressOfNames + i * 4, sizeof(DWORD));
            const WORD* ordinal = (const WORD*)rva((unsigned __int64)directory->AddressOfNameOrdinals + i * 2, sizeof(WORD));
            if (!name_rva || !ordinal || *ordinal >= directory->NumberOfFunctions) return false;
            if (rva_string(*name_rva) != name) continue;
            const DWORD* address = (const DWORD*)rva((unsigned __int64)directory->AddressOfFunctions + *ordinal * 4, sizeof(DWORD));
            if (!address || !*address) return false;
            *function_rva = *address;
            *forwarder = *address >= export_data.VirtualAddress &&
                (unsigned __int64)*address < (unsigned __int64)export_data.VirtualAddress + export_data.Size ?
                rva_string(*address) : "";
            return true;
        }
        return false;
    }
    std::string strings(size_t offset, size_t limit, size_t minimum) const {
        std::string out = "{\"ok\":true,\"strings\":[";
        if (offset >= size_) return out + "],\"next_file_offset\":" +
            std::to_string((unsigned long long)size_) + ",\"has_more\":false}";
        size_t emitted = 0, position = offset;
        size_t stop = (std::min)(size_, offset + (std::min)((size_t)8 * 1024 * 1024, size_ - offset));
        while (position < stop && emitted < limit) {
            size_t length = 0, width = 1;
            if (printable(data_[position])) {
                while (position + length < stop && length < 512 && printable(data_[position + length])) ++length;
            }
            if (length < minimum && position + 1 < stop && printable(data_[position]) && data_[position + 1] == 0) {
                width = 2; length = 0;
                while (position + length * 2 + 1 < stop && length < 512 &&
                    printable(data_[position + length * 2]) && data_[position + length * 2 + 1] == 0) ++length;
            }
            if (length < minimum) { ++position; continue; }
            std::string value; value.reserve(length);
            for (size_t i = 0; i < length; ++i) value += (char)data_[position + i * width];
            if (emitted++) out += ',';
            out += "{\"file_offset\":" + std::to_string((unsigned long long)position);
            unsigned __int64 address = file_address(position);
            if (address) { out += ",\"address\":"; quoted(&out, number(address)); }
            out += ",\"encoding\":\"";
            out += width == 2 ? "utf16le\"" : "ascii\"";
            out += ",\"text\":"; quoted(&out, value); out += '}';
            position += length * width;
        }
        return out + "],\"next_file_offset\":" + std::to_string((unsigned long long)position) +
            ",\"has_more\":" + (position < size_ ? "true}" : "false}");
    }
};

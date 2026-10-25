#define wWinMain ConsoleStyleTestUnusedWinMain
#include "McpServerApp.cpp"
#include <assert.h>

int main()
{
    HANDLE read = NULL, write = NULL;
    assert(CreatePipe(&read, &write, NULL, 0));
    const std::wstring sample =
        L"| Stack | Value | Meaning |\r\n"
        L"|---|---|---|\r\n"
        L"| [ESP+4] | **0x03BB4820** | lpFileName |\r\n"
        L"\u8fd4\u56de\u5730\u5740 0x0605BA62\r\n"
        L"C:\\Program Files (x86)\\Google\\Google Pinyin "
        L"{\"context_excerpt\":true,\"head\":\"{\\\"ok\\\":true}\"}\r\n"
        L"```json\r\n{\"path\":\"C:\\\\data\\\\file.txt\",\"count\":12}\r\n```\r\n";
    ConsoleTextStyleState state;
    for (size_t i = 0; i < sample.size(); i += 7)
        ConsoleWriteStyled(write, sample.substr(i, (std::min)(size_t(7), sample.size() - i)), &state);
    ConsoleWriteStyled(write, L"", &state, true);
    ConsoleWriteContent(write, L"{ \"key\": 12, \"path\": \"C:\\\\data\\\\file.txt\" }");
    ConsoleWriteStyled(write, L"inline { \"count\": 2 }", &state, true);
    CloseHandle(write);
    std::string actual;
    char buffer[512];
    DWORD count = 0;
    while (ReadFile(read, buffer, sizeof(buffer), &count, NULL) && count)
        actual.append(buffer, count);
    CloseHandle(read);
    assert(actual == WideToUtf8((sample + L"{ \"key\": 12, \"path\": \"C:\\\\data\\\\file.txt\" }inline { \"count\": 2 }").c_str()));
    size_t begin = 0, end = 0;
    assert(ConsolePathToken(L"C:\\Program Files (x86)\\Google\\Google Pinyin", &begin, &end));
    assert(begin == 0 && end == wcslen(L"C:\\Program Files (x86)\\Google\\Google Pinyin"));
    return 0;
}

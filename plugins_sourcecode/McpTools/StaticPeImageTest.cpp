#include "StaticPeImage.h"
#include <assert.h>

int main()
{
    wchar_t path[MAX_PATH];
    assert(GetModuleFileNameW(NULL, path, MAX_PATH));
    StaticPeImage image;
    assert(image.open(path));
    ModelJson result;
    assert(ModelJson::parse(image.info(path), &result));
    assert(result.get("ok") && result.get("ok")->value == "true");
    assert(result.get("entry_point") && result.get("section_count"));
    const std::string address = result.get("entry_point")->value;
    unsigned __int64 entry = _strtoui64(address.c_str(), NULL, 16);
    assert(ModelJson::parse(image.bytes(entry, 1), &result));
    assert(result.get("ok") && result.get("ok")->value == "true");
    assert(ModelJson::parse(image.bytes(0xffffffffffffffffULL, 1), &result));
    assert(result.get("ok") && result.get("ok")->value == "false");
    assert(ModelJson::parse(image.sections(), &result) && result.get("sections") &&
        !result.get("sections")->items.empty());
    assert(ModelJson::parse(image.imports(0, 8), &result) && result.get("imports"));
    assert(ModelJson::parse(image.exports(0, 8), &result) && result.get("exports"));
    assert(ModelJson::parse(image.strings(0, 8, 4), &result) && result.get("strings"));
    assert(ModelJson::parse(image.strings(0x20000000, 8, 4), &result) &&
        result.get("has_more")->value == "false");
    return 0;
}

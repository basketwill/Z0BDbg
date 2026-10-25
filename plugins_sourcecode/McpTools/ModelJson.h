#pragma once

#include <string>
#include <vector>
#include <cstring>

// Small JSON reader for model responses and MCP tool definitions.
struct ModelJson {
    enum Kind { INVALID, NIL, BOOLEAN, NUMBER, STRING, ARRAY, OBJECT } kind;
    std::string value;
    std::string raw;
    std::vector<ModelJson> items;
    std::vector<std::string> keys;

    ModelJson() : kind(INVALID) {}

    const ModelJson* get(const char* key) const {
        if (kind != OBJECT) return NULL;
        for (size_t i = 0; i < keys.size(); ++i)
            if (keys[i] == key) return &items[i];
        return NULL;
    }

    static bool parse(const std::string& input, ModelJson* result) {
        if (!result) return false;
        *result = ModelJson();
        size_t pos = 0;
        return read(input, &pos, result, 0) && (skip(input, &pos), pos == input.size());
    }

    static void quote(std::string* out, const std::string& value) {
        static const char hex[] = "0123456789abcdef";
        *out += '"';
        for (size_t i = 0; i < value.size(); ++i) {
            unsigned char ch = (unsigned char)value[i];
            if (ch == '"' || ch == '\\') { *out += '\\'; *out += (char)ch; }
            else if (ch == '\n') *out += "\\n";
            else if (ch == '\r') *out += "\\r";
            else if (ch == '\t') *out += "\\t";
            else if (ch < 0x20) {
                *out += "\\u00";
                *out += hex[ch >> 4];
                *out += hex[ch & 15];
            }
            else *out += (char)ch;
        }
        *out += '"';
    }

    static std::string pretty(const std::string& input) {
        ModelJson node;
        if (!parse(input, &node)) return input;
        std::string output;
        writePretty(node, 0, &output);
        return output;
    }

private:
    static void writePretty(const ModelJson& node, int depth, std::string* output) {
        if (node.kind != OBJECT && node.kind != ARRAY) {
            if (node.kind == STRING) quote(output, node.value);
            else *output += node.raw;
            return;
        }
        bool object = node.kind == OBJECT;
        *output += object ? '{' : '[';
        for (size_t i = 0; i < node.items.size(); ++i) {
            *output += i ? ",\r\n" : "\r\n";
            output->append((depth + 1) * 2, ' ');
            if (object) {
                quote(output, node.keys[i]);
                *output += ": ";
            }
            writePretty(node.items[i], depth + 1, output);
        }
        if (!node.items.empty()) {
            *output += "\r\n";
            output->append(depth * 2, ' ');
        }
        *output += object ? '}' : ']';
    }

    static void skip(const std::string& s, size_t* p) {
        while (*p < s.size() && (s[*p] == ' ' || s[*p] == '\n' || s[*p] == '\r' || s[*p] == '\t')) ++*p;
    }
    static int digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
    static bool unicode(const std::string& s, size_t* p, unsigned* cp) {
        if (*p + 4 > s.size()) return false;
        *cp = 0;
        for (int i = 0; i < 4; ++i) {
            int d = digit(s[(*p)++]);
            if (d < 0) return false;
            *cp = (*cp << 4) | d;
        }
        return true;
    }
    static void utf8(std::string* out, unsigned cp) {
        if (cp < 0x80) *out += (char)cp;
        else if (cp < 0x800) {
            *out += (char)(0xc0 | (cp >> 6));
            *out += (char)(0x80 | (cp & 63));
        }
        else if (cp < 0x10000) {
            *out += (char)(0xe0 | (cp >> 12));
            *out += (char)(0x80 | ((cp >> 6) & 63));
            *out += (char)(0x80 | (cp & 63));
        }
        else {
            *out += (char)(0xf0 | (cp >> 18));
            *out += (char)(0x80 | ((cp >> 12) & 63));
            *out += (char)(0x80 | ((cp >> 6) & 63));
            *out += (char)(0x80 | (cp & 63));
        }
    }
    static bool readString(const std::string& s, size_t* p, std::string* value) {
        if (*p >= s.size() || s[(*p)++] != '"') return false;
        while (*p < s.size()) {
            unsigned char c = (unsigned char)s[(*p)++];
            if (c == '"') return true;
            if (c < 0x20) return false;
            if (c != '\\') { *value += (char)c; continue; }
            if (*p >= s.size()) return false;
            char e = s[(*p)++];
            if (e == '"' || e == '\\' || e == '/') *value += e;
            else if (e == 'b') *value += '\b';
            else if (e == 'f') *value += '\f';
            else if (e == 'n') *value += '\n';
            else if (e == 'r') *value += '\r';
            else if (e == 't') *value += '\t';
            else if (e == 'u') {
                unsigned cp;
                if (!unicode(s, p, &cp)) return false;
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (*p + 2 > s.size() || s[*p] != '\\' || s[*p + 1] != 'u') return false;
                    *p += 2;
                    unsigned low;
                    if (!unicode(s, p, &low) || low < 0xdc00 || low > 0xdfff) return false;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                }
                else if (cp >= 0xdc00 && cp <= 0xdfff) return false;
                utf8(value, cp);
            }
            else return false;
        }
        return false;
    }
    static bool read(const std::string& s, size_t* p, ModelJson* node, int depth) {
        if (depth > 64) return false;
        skip(s, p);
        size_t begin = *p;
        if (*p >= s.size()) return false;
        char c = s[*p];
        if (c == '{' || c == '[') {
            node->kind = c == '{' ? OBJECT : ARRAY;
            ++*p;
            skip(s, p);
            char end = c == '{' ? '}' : ']';
            if (*p < s.size() && s[*p] == end) ++*p;
            else for (;;) {
                std::string key;
                if (c == '{') {
                    if (!readString(s, p, &key)) return false;
                    skip(s, p);
                    if (*p >= s.size() || s[(*p)++] != ':') return false;
                }
                ModelJson child;
                if (!read(s, p, &child, depth + 1)) return false;
                node->items.push_back(child);
                if (c == '{') node->keys.push_back(key);
                skip(s, p);
                if (*p >= s.size()) return false;
                char sep = s[(*p)++];
                if (sep == end) break;
                if (sep != ',') return false;
                skip(s, p);
            }
        }
        else if (c == '"') {
            node->kind = STRING;
            if (!readString(s, p, &node->value)) return false;
        }
        else if (c == 't' || c == 'f' || c == 'n') {
            const char* word = c == 't' ? "true" : c == 'f' ? "false" : "null";
            size_t length = strlen(word);
            if (s.compare(*p, length, word) != 0) return false;
            *p += length;
            node->kind = c == 'n' ? NIL : BOOLEAN;
            node->value = word;
        }
        else {
            node->kind = NUMBER;
            if (c == '-') ++*p;
            if (*p >= s.size()) return false;
            if (s[*p] == '0') ++*p;
            else {
                if (s[*p] < '1' || s[*p] > '9') return false;
                while (*p < s.size() && s[*p] >= '0' && s[*p] <= '9') ++*p;
            }
            if (*p < s.size() && s[*p] == '.') {
                ++*p;
                size_t digits = *p;
                while (*p < s.size() && s[*p] >= '0' && s[*p] <= '9') ++*p;
                if (*p == digits) return false;
            }
            if (*p < s.size() && (s[*p] == 'e' || s[*p] == 'E')) {
                ++*p;
                if (*p < s.size() && (s[*p] == '+' || s[*p] == '-')) ++*p;
                size_t digits = *p;
                while (*p < s.size() && s[*p] >= '0' && s[*p] <= '9') ++*p;
                if (*p == digits) return false;
            }
            node->value = s.substr(begin, *p - begin);
        }
        node->raw = s.substr(begin, *p - begin);
        return true;
    }
};

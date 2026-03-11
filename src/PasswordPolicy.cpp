#include "PasswordPolicy.h"

#include <algorithm>
#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace passfiltex {
namespace {

std::wstring ToLower(const std::wstring& input) {
    std::wstring out = input;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return out;
}

std::wstring Trim(const std::wstring& input) {
    size_t start = 0;
    while (start < input.size() && std::iswspace(input[start])) {
        ++start;
    }

    size_t end = input.size();
    while (end > start && std::iswspace(input[end - 1])) {
        --end;
    }

    return input.substr(start, end - start);
}

std::wstring NormalizeForDictionary(const std::wstring& input) {
    std::wstring lower = ToLower(input);
    for (wchar_t& c : lower) {
        switch (c) {
            case L'0':
                c = L'o';
                break;
            case L'1':
                c = L'l';
                break;
            case L'$':
                c = L's';
                break;
            case L'@':
                c = L'a';
                break;
            default:
                break;
        }
    }
    return lower;
}

bool HasRequiredClasses(const std::wstring& password) {
    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSymbol = false;

    for (wchar_t c : password) {
        if (c >= L'a' && c <= L'z') {
            hasLower = true;
        } else if (c >= L'A' && c <= L'Z') {
            hasUpper = true;
        } else if (c >= L'0' && c <= L'9') {
            hasDigit = true;
        } else {
            hasSymbol = true;
        }
    }

    return hasLower && hasUpper && hasDigit && hasSymbol;
}

bool IsAsciiLowerLetterOrDigit(wchar_t c) {
    return (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9');
}

bool IsNextLetter(wchar_t a, wchar_t b) {
    return (a >= L'a' && a <= L'z' && b >= L'a' && b <= L'z' && (b == a + 1));
}

bool IsNextDigitWithWrap(wchar_t a, wchar_t b) {
    if (!(a >= L'0' && a <= L'9' && b >= L'0' && b <= L'9')) {
        return false;
    }
    int da = static_cast<int>(a - L'0');
    int db = static_cast<int>(b - L'0');
    return ((da + 1) % 10) == db;
}

bool Has3Consecutive(const std::wstring& password) {
    if (password.size() < 3) {
        return false;
    }

    std::wstring lower = ToLower(password);
    for (size_t i = 0; i + 2 < lower.size(); ++i) {
        wchar_t c1 = lower[i];
        wchar_t c2 = lower[i + 1];
        wchar_t c3 = lower[i + 2];

        if (!IsAsciiLowerLetterOrDigit(c1) || !IsAsciiLowerLetterOrDigit(c2) || !IsAsciiLowerLetterOrDigit(c3)) {
            continue;
        }

        bool letters = IsNextLetter(c1, c2) && IsNextLetter(c2, c3);
        bool digits = IsNextDigitWithWrap(c1, c2) && IsNextDigitWithWrap(c2, c3);
        if (letters || digits) {
            return true;
        }
    }

    return false;
}

wchar_t NormalizeForRepetition(wchar_t c) {
    c = static_cast<wchar_t>(std::towlower(c));
    switch (c) {
        case L'!':
            return L'1';
        case L'@':
            return L'2';
        case L'#':
            return L'3';
        case L'$':
            return L'4';
        case L'%':
            return L'5';
        case L'^':
            return L'6';
        case L'&':
            return L'7';
        case L'*':
            return L'8';
        case L'(':
            return L'9';
        case L')':
            return L'0';
        default:
            return c;
    }
}

bool IsRepeatComparable(wchar_t c) {
    return (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9');
}

bool Has3RepeatedPattern(const std::wstring& password) {
    if (password.size() < 3) {
        return false;
    }

    for (size_t i = 0; i + 2 < password.size(); ++i) {
        wchar_t c1 = NormalizeForRepetition(password[i]);
        wchar_t c2 = NormalizeForRepetition(password[i + 1]);
        wchar_t c3 = NormalizeForRepetition(password[i + 2]);

        if (!IsRepeatComparable(c1) || !IsRepeatComparable(c2) || !IsRepeatComparable(c3)) {
            continue;
        }

        if ((c1 == c2 && c2 == c3) || (c1 == c3)) {
            return true;
        }
    }

    return false;
}

const std::unordered_map<wchar_t, wchar_t>& KeyboardNormalizeMap() {
    static const std::unordered_map<wchar_t, wchar_t> map = {
        {L'~', L'`'}, {L'!', L'1'}, {L'@', L'2'}, {L'#', L'3'}, {L'$', L'4'},
        {L'%', L'5'}, {L'^', L'6'}, {L'&', L'7'}, {L'*', L'8'}, {L'(', L'9'},
        {L')', L'0'}, {L'_', L'-'}, {L'+', L'='},
        {L'{', L'['}, {L'}', L']'}, {L'|', L'\\'},
        {L':', L';'}, {L'"', L'\''},
        {L'<', L','}, {L'>', L'.'}, {L'?', L'/'}
    };
    return map;
}

wchar_t NormalizeKeyboardChar(wchar_t c) {
    c = static_cast<wchar_t>(std::towlower(c));
    const auto& map = KeyboardNormalizeMap();
    auto it = map.find(c);
    return it == map.end() ? c : it->second;
}

const std::unordered_set<std::wstring>& VerticalKeyboardPatterns() {
    static const std::unordered_set<std::wstring> patterns = {
        L"1qaz", L"2wsx", L"3edc", L"4rfv", L"5tgb", L"6yhn", L"7ujm", L"8ik,", L"9ol.", L"0p;/",
        L"zaq1", L"xsw2", L"cde3", L"vfr4", L"bgt5", L"nhy6", L"mju7", L",ki8", L".lo9", L"/;p0"
    };
    return patterns;
}

bool Has4VerticalKeyboardSequence(const std::wstring& password) {
    if (password.size() < 4) {
        return false;
    }

    std::wstring normalized;
    normalized.reserve(password.size());
    for (wchar_t c : password) {
        normalized.push_back(NormalizeKeyboardChar(c));
    }

    const auto& patterns = VerticalKeyboardPatterns();
    for (size_t i = 0; i + 3 < normalized.size(); ++i) {
        if (patterns.find(normalized.substr(i, 4)) != patterns.end()) {
            return true;
        }
    }

    return false;
}

const std::unordered_set<std::wstring>& BuiltinDictionary() {
    static const std::unordered_set<std::wstring> words = {
        L"pass", L"root", L"admin", L"qwer", L"asdf", L"iloveyou"
    };
    return words;
}

std::unordered_set<std::wstring> g_dynamicDictionary;
std::once_flag g_dictionaryInit;

void LoadDynamicDictionary() {
#ifdef _WIN32
    wchar_t systemRootBuffer[MAX_PATH] = {0};
    DWORD len = GetEnvironmentVariableW(L"SystemRoot", systemRootBuffer, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return;
    }
    std::wstring path = std::wstring(systemRootBuffer) + L"\\System32\\PassFiltExDict.txt";
#else
    const char* systemRoot = std::getenv("SystemRoot");
    if (systemRoot == nullptr || systemRoot[0] == '\0') {
        return;
    }
    std::wstring path;
    for (const char* p = systemRoot; *p != '\0'; ++p) {
        path.push_back(static_cast<unsigned char>(*p));
    }
    path += L"/System32/PassFiltExDict.txt";
#endif

    std::wifstream dictFile{std::filesystem::path(path)};
    if (!dictFile.is_open()) {
        return;
    }

    std::wstring line;
    while (std::getline(dictFile, line)) {
        std::wstring token = Trim(line);
        if (token.empty() || token[0] == L'#') {
            continue;
        }

        std::wstring normalized = NormalizeForDictionary(token);
        if (normalized.size() >= 3) {
            g_dynamicDictionary.insert(normalized);
        }
    }
}

const std::unordered_set<std::wstring>& DynamicDictionary() {
    std::call_once(g_dictionaryInit, LoadDynamicDictionary);
    return g_dynamicDictionary;
}

std::vector<std::wstring> Tokenize(const std::wstring& text) {
    std::vector<std::wstring> tokens;
    std::wstring current;

    for (wchar_t c : ToLower(text)) {
        if ((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9')) {
            current.push_back(c);
        } else if (!current.empty()) {
            if (current.size() >= 3) {
                tokens.push_back(current);
            }
            current.clear();
        }
    }

    if (!current.empty() && current.size() >= 3) {
        tokens.push_back(current);
    }

    return tokens;
}

bool ContainsAnyDictionaryTerm(const std::wstring& normalizedPassword) {
    for (const auto& word : BuiltinDictionary()) {
        if (normalizedPassword.find(word) != std::wstring::npos) {
            return true;
        }
    }

    for (const auto& word : DynamicDictionary()) {
        if (normalizedPassword.find(word) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool ContainsAccountContext(const std::wstring& normalizedPassword, const PolicyContext& context) {
    if (!context.accountName.empty()) {
        std::wstring account = NormalizeForDictionary(context.accountName);
        if (account.size() >= 3 && normalizedPassword.find(account) != std::wstring::npos) {
            return true;
        }
    }

    for (const std::wstring& token : Tokenize(context.fullName)) {
        std::wstring normalizedToken = NormalizeForDictionary(token);
        if (normalizedToken.size() >= 3 && normalizedPassword.find(normalizedToken) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

} // namespace

bool ValidatePasswordPolicy(const std::wstring& password, const PolicyContext& context) {
    if (!HasRequiredClasses(password)) {
        return false;
    }
    if (Has3Consecutive(password)) {
        return false;
    }
    if (Has3RepeatedPattern(password)) {
        return false;
    }
    if (Has4VerticalKeyboardSequence(password)) {
        return false;
    }

    std::wstring normalizedPassword = NormalizeForDictionary(password);
    if (ContainsAnyDictionaryTerm(normalizedPassword)) {
        return false;
    }
    if (ContainsAccountContext(normalizedPassword, context)) {
        return false;
    }

    return true;
}

} // namespace passfiltex

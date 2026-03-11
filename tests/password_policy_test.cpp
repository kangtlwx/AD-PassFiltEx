#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "../src/PasswordPolicy.h"

struct Case {
    std::wstring password;
    bool expected;
    std::wstring account;
    std::wstring fullname;
    const char* name;
};

bool RunCases(const std::vector<Case>& cases) {
    int failures = 0;
    for (const auto& c : cases) {
        passfiltex::PolicyContext context;
        context.accountName = c.account;
        context.fullName = c.fullname;

        bool actual = passfiltex::ValidatePasswordPolicy(c.password, context);
        if (actual != c.expected) {
            std::wcerr << L"[FAIL] " << c.name << L" expected=" << c.expected << L" actual=" << actual << L"\n";
            failures++;
        }
    }

    return failures == 0;
}

int main() {
    std::vector<Case> defaultCases = {
        {L"Aa9!xY7#", true, L"", L"", "valid basic"},
        {L"aa9!xy7#", false, L"", L"", "missing uppercase"},
        {L"Aa123!Z#", false, L"", L"", "ascending digits"},
        {L"Aa890!Z#", false, L"", L"", "ascending digits wrap"},
        {L"Aaabc!9#", false, L"", L"", "ascending letters"},
        {L"Aa111!Z#", false, L"", L"", "three repeated adjacent"},
        {L"Aaqgq!9#", false, L"", L"", "repeated aba pattern"},
        {L"Aa1qaz!9#", false, L"", L"", "vertical keyboard"},
        {L"AaR00t!9#", false, L"", L"", "dictionary with normalization"},
        {L"AaSkyBlue!9#", false, L"skyblue", L"", "contains account name"},
        {L"AaTechLead!9#", false, L"", L"Tech Lead", "contains full name token"}
    };

    if (!RunCases(defaultCases)) {
        return 1;
    }

#ifndef _WIN32
    setenv("PASSFILTEX_BLOCK_CONSECUTIVE3", "0", 1);
    Case consecutiveOff{L"Aa123!Z#", true, L"", L"", "consecutive disabled by env"};
    if (!RunCases({consecutiveOff})) {
        return 1;
    }
    unsetenv("PASSFILTEX_BLOCK_CONSECUTIVE3");
#endif

    std::cout << "All password policy tests passed\n";
    return 0;
}

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

int main() {
    std::vector<Case> cases = {
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

    if (failures == 0) {
        std::cout << "All password policy tests passed\n";
        return 0;
    }

    std::cerr << failures << " cases failed\n";
    return 1;
}

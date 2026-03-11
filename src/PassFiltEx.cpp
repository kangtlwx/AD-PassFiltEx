#include <windows.h>
#include <ntsecapi.h>

#include <string>

#include "PasswordPolicy.h"

namespace {

constexpr NTSTATUS kNtStatusSuccess = 0;

std::wstring UnicodeStringToWstring(PUNICODE_STRING str) {
    if (str == nullptr || str->Buffer == nullptr || str->Length == 0) {
        return L"";
    }
    return std::wstring(str->Buffer, str->Length / sizeof(wchar_t));
}

} // namespace

extern "C" __declspec(dllexport) BOOLEAN __stdcall InitializeChangeNotify(void) {
    return TRUE;
}

extern "C" __declspec(dllexport) NTSTATUS __stdcall PasswordChangeNotify(
    PUNICODE_STRING /*UserName*/,
    ULONG /*RelativeId*/,
    PUNICODE_STRING /*NewPassword*/
) {
    return kNtStatusSuccess;
}

extern "C" __declspec(dllexport) BOOLEAN __stdcall PasswordFilter(
    PUNICODE_STRING AccountName,
    PUNICODE_STRING FullName,
    PUNICODE_STRING Password,
    BOOLEAN /*SetOperation*/
) {
    passfiltex::PolicyContext context;
    context.accountName = UnicodeStringToWstring(AccountName);
    context.fullName = UnicodeStringToWstring(FullName);

    std::wstring password = UnicodeStringToWstring(Password);
    return passfiltex::ValidatePasswordPolicy(password, context) ? TRUE : FALSE;
}

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD /*ul_reason_for_call*/, LPVOID /*lpReserved*/) {
    return TRUE;
}

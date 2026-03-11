#pragma once

#include <string>

namespace passfiltex {

struct PolicyContext {
    std::wstring accountName;
    std::wstring fullName;
};

bool ValidatePasswordPolicy(const std::wstring& password, const PolicyContext& context);

} // namespace passfiltex

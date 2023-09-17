#pragma once

#include <string>

namespace str {
constexpr wchar_t hex[] = L"abcdef0123456789";

std::wstring wrand(u32 length, u64 seed, const wchar_t* table);
std::string rand(u32 length, u64 seed, const wchar_t* table);
}
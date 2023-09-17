#include <string.hpp>

std::wstring str::wrand(u32 length, u64 seed, const wchar_t* table) {
  u32 table_length = wcslen(table);

  std::wstring result;
  for (u32 i = 0; i < length; ++i) {
    u32 pseudo = ((seed + i) ^ 0x4447bbee) ^ 0x092cd4af;
    result.push_back(table[pseudo % table_length]);
  }

  return result;
}

std::string str::rand(u32 length, u64 seed, const wchar_t* table) {
  std::wstring result = wrand(length, seed, table);
  return {result.begin(), result.end()};
}

#pragma once

#include <intrin.h>

namespace crypto {
template <typename T>
constexpr u32 hash(const T* str) {
  u32 hash = 0;
  T* p = (T*)str;
  while (*p) {
    if constexpr (sizeof(T) == sizeof(char)) {
      hash = _mm_crc32_u8(hash, *p);
    } else if constexpr (sizeof(T) == sizeof(wchar_t)) {
      hash = _mm_crc32_u16(hash, *p);
    }

    hash ^= *p;
    hash ^= 0x4447bbee;
    hash = (hash >> 1);
    hash ^= 0x092cd4af;
    hash += (hash << 5);

    ++p;
  }

  return hash;
}

template <typename T>
u32 run_hash(const T* str) {
  u32 hash = 0;
  T* p = (T*)str;
  while (*p) {
    if (sizeof(T) == sizeof(char)) {
      hash = _mm_crc32_u8(hash, *p);
    } else if (sizeof(T) == sizeof(wchar_t)) {
      hash = _mm_crc32_u16(hash, *p);
    }

    hash ^= *p;
    hash ^= 0x4447bbee;
    hash = (hash >> 1);
    hash ^= 0x092cd4af;
    hash += (hash << 5);

    ++p;
  }

  return hash;
}
}  // namespace crypto

#define h(str) crypto::hash(str)
#define rh(str) crypto::run_hash(str)
#pragma once

namespace crypto {
template <typename T>
constexpr u32 hash(const T* str) {
  u32 hash = 0;
  T* p = (T*)str;
  while (*p) {
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

#define h(str)                                       \
  []() {                                             \
    constexpr static u32 value = crypto::hash(str); \
    return value;                                    \
  }()

#define rh(str) crypto::run_hash(str)       
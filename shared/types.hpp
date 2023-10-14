#pragma once

#include <intrin.h>

#include <__msvc_int128.hpp>

typedef char s8;
typedef short s16;
typedef int s32;
typedef long long s64;
typedef std::_Signed128 s128;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef std::_Unsigned128 u128;

typedef float float32;
typedef double float64;

#pragma pack(push, 1)
struct section_t {
  struct {
    bool encrypted : 1;
    bool integrity : 1;
    bool guarded : 1;
  };

  u32 crc;
  u32 va;
  u32 size;
};

struct pyld_ctx_t {
  u128 key;
  u32 ep;
  u8 section_count;

  struct {
    bool find_vm : 1;
    bool find_dbg : 1;
    bool sec_integrity : 1;
    bool sec_guard : 1;
    bool sec_encrypt : 1;
  };

  section_t sections[32];
};
#pragma pack(pop)

static __forceinline u8 enc8(u8 value, u128 key) {
  u64 lower = (u64)(key >> 64);
  u64 upper = (u64)key;

  value ^= upper;
  value += lower;
  return value;
}

static __forceinline u8 dec8(u8 value, u128 key) {
  u64 lower = (u64)(key >> 64);
  u64 upper = (u64)key;

  value -= lower;
  value ^= upper;
  return value;
}

static __forceinline u64 enc64(u64 value, u128 key) {
  return value ^ (u32)key;
}

static __forceinline u64 dec64(u64 value, u128 key) { return value ^ (u32)key; }

static __forceinline void CryptContext(u64 base, pyld_ctx_t* ctx) {
  u32 key = 0;
  for (u8 i = 0; i < 100; ++i) {
    key = _mm_crc32_u8(key, *(u8*)(base + i));
  }

  u8* bytes = (u8*)ctx;
  for (u16 i = 0; i < sizeof(pyld_ctx_t); ++i) {
    bytes[i] ^= key;
  }
}
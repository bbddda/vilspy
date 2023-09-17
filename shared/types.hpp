#pragma once

#include <intrin.h>
#include <windows.h>

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
    u8 encoded : 1;
    u8 integrity : 1;
    u8 guard : 1;
  };

  u32 crc;
  u32 va;
  u32 size;
};

struct pyld_ctx_t {
  struct {
    u32 key0 : 22;
    u32 key1 : 24;
    u32 key2 : 18;
  };

  u32 ep;
  u8 section_count : 6;
  section_t sections[10];
};
#pragma pack(pop)

static __forceinline u8 enc8(u8 value, u32 key1, u32 key2, u32 key3) {
  value ^= (u8)(key1 & 0xff);
  value += (u8)(key2 & 0xff);
  value = _rotr8(value, (u8)(key3 & 0x7));
  return value;
}

static __forceinline u8 dec8(u8 value, u32 key1, u32 key2, u32 key3) {
  value = _rotl8(value, (u8)(key3 & 0x7));
  value -= (u8)(key2 & 0xff);
  value ^= (u8)(key1 & 0xff);
  return value;
}

static __forceinline u64 enc64(u64 value, u32 key1, u32 key2, u32 key3) {
  value ^= key1 * key3;
  value += key2;
  return value;
}

static __forceinline u64 dec64(u64 value, u32 key1, u32 key2, u32 key3) {
  value -= key2;
  value ^= key1 * key3;
  return value;
}

static __forceinline void CryptContext(u64 base, pyld_ctx_t* ctx) {
  u32 key = 0;
  for (u16 i = 0; i < 100; ++i) {
    key = _mm_crc32_u8(key, *(u8*)(base + i));
  }

  u8* bytes = (u8*)ctx;
  for (u8 i = 0; i < sizeof(pyld_ctx_t); ++i) {
    bytes[i] ^= key;
  }
}
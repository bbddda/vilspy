#pragma once

#include <__msvc_int128.hpp>
#include <windows.h>
#include <tuple>
#include <intrin.h>

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

struct section_t {
  u32 crc_dec;
  u32 crc_size;
  u32 va;
  u32 size;
};

struct pyld_ctx_t {
  struct {
    u32 key0 : 22;
    u32 key2 : 18;
    u32 key1 : 24;
  };

  u32 ep;
  u8 section_count : 2;
  section_t sections[4];
};

static u8 enc8(u8 value, u32 key1, u32 key2, u32 key3) {
  value ^= (u8)(key1 & 0xff);
    value += (u8)(key2 & 0xff);
    value = _rotr8(value, (u8)(key3 & 0x7));
    return value;
}

static u8 dec8(u8 value, u32 key1, u32 key2, u32 key3) {
    value = _rotl8(value, (u8)(key3 & 0x7));
    value -= (u8)(key2 & 0xff);
    value ^= (u8)(key1 & 0xff);
    return value;
}
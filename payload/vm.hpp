#pragma once

namespace vm {
void* memcpy(void* dst, void const* src, u64 size);
void* memset(void* ptr, u8 value, u64 size);
s32 memcmp(void const* dst, void const* src, u64 size);
}
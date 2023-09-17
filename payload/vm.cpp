#include <vm.hpp>

void* vm::memcpy(void* dst, void const* src, u64 size) {
  for (u64 i = 0; i < size; ++i) {
    *(u8*)((u64)dst + i) = *(u8*)((u64)src + i);
  }

  return dst;
}

void* vm::memset(void* ptr, u8 value, u64 size) {
  for (u64 i = 0; i < size; ++i) {
    *(u8*)((u64)ptr + i) = value;
  }
  return ptr;
}

s32 vm::memcmp(void const* dst, void const* src, u64 size) {
  u8* p1 = (u8*)dst;
  u8* p2 = (u8*)src;

  for (u64 i = 0; i < size; ++i) {
    if (p1[i] != p2[i]) {
      return p1[i] - p2[i];
    }
  }

  return 0;
}

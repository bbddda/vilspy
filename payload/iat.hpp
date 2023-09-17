#pragma once

#include <Windows.h>

namespace iat {
  u64 FindExport(u64 base, u32 hash);
  u64 Find(u32 hash);
};

#define nt(func) reinterpret_cast<decltype(&func)>(iat::Find(h(###func)))
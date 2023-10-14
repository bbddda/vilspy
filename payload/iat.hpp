#pragma once

#include <Windows.h>
#include <crypto.hpp>
#include <types.hpp>

extern PEB64* g_peb;

namespace iat {
u64 __forceinline FindExport(u64 base, u32 hash) {
  auto dos = (IMAGE_DOS_HEADER*)base;
  auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

  auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!dir.VirtualAddress) return 0;

  auto eat = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
  u32* functions = (u32*)(base + eat->AddressOfFunctions);
  u32* names = (u32*)(base + eat->AddressOfNames);
  u16* ordinals = (u16*)(base + eat->AddressOfNameOrdinals);

  for (u32 i = 0; i < eat->NumberOfNames; ++i) {
    const char* name = (char*)(base + names[i]);
    if (rh(name) == hash) {
      return base + functions[ordinals[i]];
    }
  }

  return 0;
}

u64 __forceinline Find(u32 hash) {
  LIST_ENTRY* head = &g_peb->Ldr->InMemoryOrderModuleList;
  for (auto curr = head->Flink; curr != head; curr = curr->Flink) {
    auto entry = RECORD(curr, FULL_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    u64 func = FindExport((u64)entry->DllBase, hash);
    if (func) return func;
  }

  return 0;
}

};

#define nt(func) reinterpret_cast<decltype(&func)>(iat::Find(h(###func)))
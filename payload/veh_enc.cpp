#include <docs.hpp>
#include <globals.hpp>
#include <iat.hpp>
#include <mutex>
#include <types.hpp>
#include <veh_enc.hpp>

void veh_enc::ProtectPage(uint64_t base) {
  DWORD old;
  g_VirtualProtect((void*)base, PAGE_SIZE, PAGE_READWRITE, &old);

  u8* data = (u8*)base;
  for (u16 i = 0; i < PAGE_SIZE; ++i) {
    data[i] = enc8(data[i], g_key);
  }

  g_VirtualProtect((void*)base, PAGE_SIZE, PAGE_NOACCESS, &old);
}

void veh_enc::UnProtectPage(uint64_t base) {
  DWORD old;
  g_VirtualProtect((void*)base, PAGE_SIZE, PAGE_READWRITE, &old);

  u8* data = (u8*)base;
  for (u16 i = 0; i < PAGE_SIZE; ++i) {
    data[i] = dec8(data[i], g_key);
  }

  g_VirtualProtect((void*)base, PAGE_SIZE, PAGE_EXECUTE_READ, &old);
}

LONG NTAPI veh_enc::OnException(EXCEPTION_POINTERS* ctx) {
  s32 code = EXCEPTION_CONTINUE_SEARCH;
  g_RtlEnterCriticalSection(&g_critical);

  u64 page = ctx->ExceptionRecord->ExceptionInformation[1] & ~0xFFF;
  if (ctx->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    if (g_prev_page) {
      ProtectPage(g_prev_page);
    }

    UnProtectPage(page);
    g_prev_page = page;
    code = EXCEPTION_CONTINUE_EXECUTION;
  }

  g_RtlLeaveCriticalSection(&g_critical);
  return code;
}

void veh_enc::GuardPage(u64 base) {
  DWORD old;
  nt(VirtualProtect)((void*)base, PAGE_SIZE, PAGE_NOACCESS, &old);
}

bool veh_enc::Install(u128 key) {
  g_VirtualProtect = nt(VirtualProtect);
  g_RtlEnterCriticalSection = nt(RtlEnterCriticalSection);
  g_RtlLeaveCriticalSection = nt(RtlLeaveCriticalSection);
  g_key = key;
  g_prev_page = 0;

  nt(RtlInitializeCriticalSection)(&g_critical);
  return nt(RtlAddVectoredExceptionHandler)(1, &OnException);
}
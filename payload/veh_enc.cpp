#include <docs.hpp>
#include <globals.hpp>
#include <iat.hpp>
#include <mutex>
#include <veh_enc.hpp>

bool veh_enc::guarded_page_c::Protect() {
  DWORD old;
  if (!nt(VirtualProtect)((void*)m_base, PAGE_SIZE, PAGE_READWRITE, &old)) {
    return false;
  }

  u8* data = (u8*)m_base;
  for (u16 i = 0; i < PAGE_SIZE; ++i) {
    data[i] = enc8(data[i], g_ctx.key0, g_ctx.key1, g_ctx.key2);
  }

  m_crypted = true;
  return nt(VirtualProtect)((void*)m_base, PAGE_SIZE, PAGE_NOACCESS, &old);
}

bool veh_enc::guarded_page_c::UnProtect() {
  DWORD old;
  if (!nt(VirtualProtect)((void*)m_base, PAGE_SIZE, PAGE_READWRITE, &old)) {
    return false;
  }

  u8* data = (u8*)m_base;
  for (u16 i = 0; i < PAGE_SIZE; ++i) {
    data[i] = dec8(data[i], g_ctx.key0, g_ctx.key1, g_ctx.key2);
  }

  m_crypted = false;
  return nt(VirtualProtect)((void*)m_base, PAGE_SIZE, m_protect, &old);
}

veh_enc::guarded_page_c* veh_enc::FindPage(u64 addr) {
  for (u64 i = 0; i < g_protected_pages.GetSize(); ++i) {
    auto page = &g_protected_pages[i];
    if (addr >= page->m_base && addr < page->m_base + PAGE_SIZE) {
      return page;
    }
  }

  return nullptr;
}

CRITICAL_SECTION g_critical;
LONG NTAPI veh_enc::OnException(EXCEPTION_POINTERS* ctx) {
  nt(RtlEnterCriticalSection)(&g_critical);

  if (ctx->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    auto page = FindPage(ctx->ExceptionRecord->ExceptionInformation[1]);
    if (page) {
      if (g_unprotected_pages.GetSize() == 2) {
        g_unprotected_pages[0]->Protect();
        g_unprotected_pages.Delete(0);
      }

      if (page->m_crypted) {
        page->UnProtect();
        g_unprotected_pages.PushBack(page);
      }

      nt(RtlLeaveCriticalSection)(&g_critical);
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }

  nt(RtlLeaveCriticalSection)(&g_critical);
  return EXCEPTION_CONTINUE_SEARCH;
}

bool veh_enc::GuardPage(u64 base) {
  DWORD protect;
  if (!nt(VirtualProtect)((void*)base, PAGE_SIZE, PAGE_NOACCESS, &protect)) {
    return false;
  }

  guarded_page_c inst;
  inst.m_base = base;
  inst.m_protect = protect;
  inst.m_crypted = true;
  g_protected_pages.PushBack(inst);
  return true;
}

bool veh_enc::Install(const pyld_ctx_t& ctx) {
  g_ctx = ctx;
  nt(RtlInitializeCriticalSection)(&g_critical);
  return nt(RtlAddVectoredExceptionHandler)(1, &OnException) == &OnException;
}
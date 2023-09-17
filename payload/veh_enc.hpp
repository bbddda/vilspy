#pragma once

#include <Windows.h>

#include <vector.hpp>

void __cdecl atexit();

namespace veh_enc {
class guarded_page_c {
 public:
  u64 m_base;
  u32 m_protect;
  bool m_crypted;

  bool Protect();
  bool UnProtect();
};

inline pyld_ctx_t g_ctx;
inline vector<guarded_page_c> g_protected_pages;
inline vector<guarded_page_c*> g_unprotected_pages;

guarded_page_c* FindPage(u64 addr);

LONG NTAPI OnException(EXCEPTION_POINTERS* ctx);
bool GuardPage(u64 base);
bool Install(const pyld_ctx_t& ctx);
}  // namespace veh_enc
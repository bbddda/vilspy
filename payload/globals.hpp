#pragma once

#include <Windows.h>
#include <types.hpp>
#include <iat.hpp>
#include <xorstr.hpp>

extern "C" {
__declspec(dllexport) inline pyld_ctx_t e_ctx = {.ep = 0xFF};
inline u64 g_base = 0;
inline PEB64* g_peb = nullptr;
}

#define THROW_ERROR(msg)                                         \
  []() {                                                         \
    auto err = xorstr(msg);                                      \
    auto title = xorstr(L"Error");                               \
    nt(MessageBoxW)(nullptr, err.crypt_get(), title.crypt_get(), \
                    MB_OK | MB_ICONERROR);                       \
    title.crypt();                                               \
    err.crypt();                                                 \
    nt(ExitProcess)(0);                                          \
  }()\

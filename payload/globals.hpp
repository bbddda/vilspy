#pragma once

#include <Windows.h>

extern "C" {
__declspec(dllexport) inline pyld_ctx_t g_ctx;
inline u64 g_base;
}
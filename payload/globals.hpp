#pragma once

#include <Windows.h>

extern "C" {
__declspec(dllexport) inline pyld_ctx_t g_ctx = {0xFF, 0xFF, 0xFF};
}
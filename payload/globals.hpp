#pragma once

#include <Windows.h>

extern "C" {
__declspec(dllexport) inline pyld_ctx_t e_ctx = {.ep = 0xFF};
}

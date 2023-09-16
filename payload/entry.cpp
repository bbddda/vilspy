#include <Windows.h>
#include <intrin.h>
#include <winternl.h>

#include <globals.hpp>

void payload_entry() {
  g_base = *(u64*)(__readgsqword(0x60) + 0x10);



  reinterpret_cast<void (*)()>(g_base + g_ctx.ep)();
}
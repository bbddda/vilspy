#include <Windows.h>
#include <intrin.h>
#include <winternl.h>

#include <docs.hpp>
#include <globals.hpp>
#include <iat.hpp>

extern "C" void __CxxFrameHandler4() { __ud2(); }
extern "C" void __std_terminate() { __ud2(); }

void payload_entry() {
  nt(LoadLibraryW)(L"user32.dll");

  PEB64* peb = (PEB64*)__readgsqword(0x60);
  if (peb->BeingDebugged) {
    nt(MessageBoxW)(nullptr, L"A debugger was found on your system.", L"Error",
                    MB_OK | MB_ICONERROR);
    return;
  }

  for (u8 i = 0; i < g_ctx.section_count; ++i) {
    section_t* sec = &g_ctx.sections[i];
    u64 start = peb->ImageBaseAddress + sec->va;
    u32 dec_crc = 0;
  
    DWORD old_prot = 0;
    nt(VirtualProtect)((void*)start, sec->size, PAGE_READWRITE, &old_prot);

    /* Encryption */
    for (u64 curr = start; curr < start + sec->size; ++curr) {
      u8* b = (u8*)curr;
      *b = dec8(*b, g_ctx.key0, g_ctx.key1, g_ctx.key2);
    }

    /* Save CRC */
    for (u64 curr = start; curr < start + sec->crc_size; ++curr) {
      dec_crc = _mm_crc32_u8(dec_crc, *(u8*)curr);
    }

    nt(VirtualProtect)((void*)start, sec->size, old_prot, &old_prot);

    if (sec->crc_dec != dec_crc) {
      nt(MessageBoxW)(nullptr, L"Invalid integrity.", L"Error",
                      MB_OK | MB_ICONERROR);
      return;
    }
  }

  return reinterpret_cast<void (*)()>(peb->ImageBaseAddress + g_ctx.ep)();
}
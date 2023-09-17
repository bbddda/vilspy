#include <Windows.h>
#include <intrin.h>
#include <winternl.h>

void __cdecl atexit() {}

#include <docs.hpp>
#include <globals.hpp>
#include <iat.hpp>
#include <vector.hpp>
#include <veh_enc.hpp>


void ThrowError(const wchar_t* message) {
  nt(MessageBoxW)(nullptr, message, L"Error", MB_OK | MB_ICONERROR);
  return nt(ExitProcess)(0);
}

void PayloadEntry() {
  nt(LoadLibraryW)(L"user32.dll");

  PEB64* peb = (PEB64*)__readgsqword(0x60);

  /* Decrypt context */
  pyld_ctx_t ctx = e_ctx;
  CryptContext(peb->ImageBaseAddress, &ctx);

  if (peb->BeingDebugged) {
    return ThrowError(L"A debugger was found on your system.");
  }

  for (u8 i = 0; i < ctx.section_count; ++i) {
    section_t* sec = &ctx.sections[i];
    u64 start = peb->ImageBaseAddress + sec->va;

    /* Encryption */
    if (!sec->guard && sec->encoded) {
      DWORD old = 0;
      nt(VirtualProtect)((void*)start, sec->size, PAGE_READWRITE, &old);

      for (u64 curr = start; curr < start + sec->size; ++curr) {
        u8* b = (u8*)curr;
        *b = dec8(*b, ctx.key0, ctx.key1, ctx.key2);
      }

      nt(VirtualProtect)((void*)start, sec->size, old, &old);
    }

    /* Save CRC */
    if (sec->integrity) {
      u32 crc = 0;
      for (u64 curr = start; curr < start + sec->size; ++curr) {
        u8 byte = *(u8*)curr;
        if (sec->guard) {
          byte = dec8(byte, ctx.key0, ctx.key1, ctx.key2);
        }

        crc = _mm_crc32_u8(crc, byte);
      }

      if (sec->crc != crc) {
        return ThrowError(L"Invalid integrity.");
      }
    }

    if (sec->guard) {
      u64 last_page_end = ALIGN_TO_PAGE_END(start + sec->size);
      for (u64 page = start; page < last_page_end; page += PAGE_SIZE) {
        veh_enc::GuardPage(page);
      }
    }
  }

  if (!veh_enc::g_protected_pages.IsEmpty()) {
    veh_enc::Install(ctx);
  }
  
  u64 dec_ep = dec64(ctx.ep, ctx.key0, ctx.key1, ctx.key2);
  return reinterpret_cast<void (*)()>(peb->ImageBaseAddress + dec_ep)();
}
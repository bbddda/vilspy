#include <Windows.h>
#include <intrin.h>
#include <winternl.h>

#include <docs.hpp>
#include <globals.hpp>
#include <iat.hpp>
#include <veh_enc.hpp>
#include <types.hpp>
#include <xorstr.hpp>

extern "C" void spoofed_jmp(u64 addr);

void PayloadEntry() {
  g_peb = (PEB64*)__readgsqword(0x60);
  g_base = g_peb->ImageBaseAddress;

  {
    auto user32 = xorstr(L"user32.dll");
    nt(LoadLibraryW)(user32.crypt_get());
    user32.crypt();
  }

  /* Decrypt context */
  pyld_ctx_t ctx = e_ctx;
  CryptContext(g_base, &ctx);

  if (ctx.find_dbg && g_peb->BeingDebugged) {
    return THROW_ERROR(L"A debugger was found on your system.");
  } else if (ctx.find_vm) {
    constexpr u32 count = 50000;

    HANDLE thread = nt(GetCurrentThread)();
    s32 old_prio = nt(GetThreadPriority)(thread);
    nt(SetThreadPriority)(thread, THREAD_PRIORITY_TIME_CRITICAL);

    u64 sum = 0;
    for (u32 i = 0; i < count; ++i) {
      u64 start = __rdtsc();

      s32 data[4];
      __cpuid(data, 0);

      u64 end = __rdtsc();
      sum += end - start;
    }

    nt(SetThreadPriority)(thread, old_prio);

    if (sum > 400 * count) {
      return THROW_ERROR(L"Virtualization software was found.");
    }
  }

  bool need_veh = false;
  for (u8 i = 0; i < ctx.section_count; ++i) {
    section_t* sec = &ctx.sections[i];
    u64 start = g_base + sec->va;

    /* Encryption */
    if (ctx.sec_encrypt && !sec->guarded && sec->encrypted) {
      DWORD old = 0;
      nt(VirtualProtect)((void*)start, sec->size, PAGE_READWRITE, &old);

      for (u64 curr = start; curr < start + sec->size; ++curr) {
        u8* b = (u8*)curr;
        *b = dec8(*b, ctx.key);
      }

      nt(VirtualProtect)((void*)start, sec->size, old, &old);
    }

    /* Integrity */
    if (ctx.sec_integrity && sec->integrity) {
      u32 crc = 0;
      for (u64 curr = start; curr < start + sec->size; ++curr) {
        u8 byte = *(u8*)curr;
        if (sec->guarded) {
          byte = dec8(byte, ctx.key);
        }

        crc = _mm_crc32_u8(crc, byte);
      }

      if (sec->crc != crc) {
        return THROW_ERROR(L"Invalid integrity.");
      }
    }

    if (ctx.sec_guard && sec->guarded) {
      u64 last_page_end = ALIGN_TO_PAGE_END(start + sec->size);
      for (u64 page = start; page < last_page_end; page += PAGE_SIZE) {
        veh_enc::GuardPage(page);
      }

      need_veh = true;
    }
  }

  if (need_veh && !veh_enc::Install(ctx.key)) {
    return THROW_ERROR(L"Code violation 0xV0000001.");
  }

  /* erase pe header */
  u64 dec_ep = dec64(ctx.ep, ctx.key);
  return reinterpret_cast<void(*)()>(g_base + dec_ep)();
}

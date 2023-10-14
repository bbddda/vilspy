#include <Windows.h>

#include <fstream>
#include <iostream>
#include <logger.hpp>
#include <pe.hpp>
#include <string.hpp>
#include <string>
#include <types.hpp>

constexpr bool find_vm = true;
constexpr bool find_dbg = true;
constexpr bool sec_integrity = true;
constexpr bool sec_guard = true;
constexpr bool sec_encrypt = true;

void InstallPayload(pe_c* pe, pe_c* pyld) {
  pyld_ctx_t* ctx = (pyld_ctx_t*)pyld->FindExport("e_ctx");
  memset(ctx, 0, sizeof(pyld_ctx_t));

  auto* obf0 = pe->InsertSection(".obf0", pyld->ImageSize(), r | w | x | c);

  /* ENVIRONMENT SETUP */

  g_logger->Log<logger_c::wait>(L"setting environment...");
  {
    if constexpr (find_vm) {
      ctx->find_vm = find_vm;
      g_logger->Log<logger_c::warn>(L"virtualization detection enabled.");
    }

    if constexpr (find_dbg) {
      ctx->find_dbg = find_dbg;
      g_logger->Log<logger_c::warn>(L"debugger detection enabled.");
    }

    if constexpr (sec_integrity) {
      ctx->sec_integrity = sec_integrity;
      g_logger->Log<logger_c::warn>(L"section integrity enabled.");
    }

    if constexpr (sec_encrypt) {
      ctx->sec_encrypt = sec_encrypt;
      g_logger->Log<logger_c::warn>(L"section encryption enabled.");
    }

    if constexpr (sec_guard) {
      ctx->sec_guard = sec_guard;
      g_logger->Log<logger_c::warn>(L"section guard enabled.");
    }

    ctx->key |= (u128)(time(nullptr) ^ GetTickCount64());
    ctx->key |= (u128)__rdtsc() << 32;
    ctx->key |= (u128)(pyld->ImageSize()) << 96;
    ctx->ep = enc64(*pe->EntryPointVA(), ctx->key);
  }

  /* SECTION PROTECTION */
  g_logger->Log<logger_c::wait>(L"protecting sections...");
  {
    g_logger->Log<logger_c::no_prefix>(L"====================");
    for (auto sec = pe->FirstSection(); sec < pe->LastSection(); ++sec) {
      g_logger->Log<logger_c::wait>(L"%S (%.2fkb):", sec->Name,
                                    sec->SizeOfRawData / 1024.00f);

      section_t* ctx_sec = &ctx->sections[ctx->section_count++];
      ctx_sec->va = sec->VirtualAddress;
      ctx_sec->size = sec->Misc.VirtualSize;

      u64 start = pe->Base() + sec->PointerToRawData;

      /* Integrity */
      if (sec_integrity) {
        bool can_integrity = (sec->Characteristics & IMAGE_SCN_CNT_CODE) &&
                             !(sec->Characteristics & IMAGE_SCN_MEM_WRITE);
        if ((ctx_sec->integrity = can_integrity)) {
          for (u64 curr = start; curr < start + ctx_sec->size; ++curr) {
            ctx_sec->crc = _mm_crc32_u8(ctx_sec->crc, *(u8*)curr);
          }

          g_logger->Log(L"Integrity Allowed.");
        }
      }

      /* Encryption */
      if (sec_encrypt) {
        bool can_encrypt = sec->Characteristics & IMAGE_SCN_CNT_CODE;
        if ((ctx_sec->encrypted = can_encrypt)) {
          for (u64 curr = start; curr < start + sec->SizeOfRawData; ++curr) {
            u8* b = (u8*)curr;
            *b = enc8(*b, ctx->key);
          }

          g_logger->Log(L"Encrypted.");
        }
      }

      /* Procedural Encryption */
      if (sec_guard) {
        bool can_guard = sec->Characteristics & IMAGE_SCN_CNT_CODE;
        if ((ctx_sec->guarded = can_guard)) {
          g_logger->Log(L"Guard Allowed.");
        }
      }

      g_logger->Log<logger_c::no_prefix>(L"====================");
    }
  }

  /* ENCRYPT CONTEXT */
  {
    g_logger->Log(L"key: 0x%llx", ctx->key);
    g_logger->Log(L"ep: 0x%x", ctx->ep);
    g_logger->Log(L"section_count: %i", ctx->section_count);
    CryptContext(pe->Base(), ctx);
  }

  /* PAYLOAD INJECTION */
  g_logger->Log<logger_c::wait>(L"setting payload...");
  {
    for (auto* sec = pyld->FirstSection(); sec <= pyld->LastSection(); ++sec) {
      u32 size = max(sec->SizeOfRawData, sec->Misc.VirtualSize);
      u64 dst = pe->Base() + obf0->PointerToRawData + sec->VirtualAddress;
      u64 src = pyld->Base() + sec->PointerToRawData;

      memcpy((void*)dst, (void*)src, size);
    }
  }

  /* ENTRYPOINT PATCH */

  g_logger->Log<logger_c::wait>(L"redirecting entry...");
  {
    u32 new_ep = obf0->VirtualAddress + *pyld->EntryPointVA();
    *pe->EntryPointVA() = new_ep;
  }
}

s32 main(s32 argc, char* argv[]) {
  if (argc < 3) {
    g_logger->Log<logger_c::err>(L"%S <input> <output>", argv[0]);
    return EXIT_FAILURE;
  }

  g_logger->Log<logger_c::wait>(L"loading file...");
  pe_c pe{argv[1]};

  g_logger->Log<logger_c::wait>(L"installing payload...");
  pe_c pyld = pe_c{"payload.dll"};
  InstallPayload(&pe, &pyld);

  g_logger->Log<logger_c::wait>(L"saving file...");
  pe.Save(argv[2]);

  return EXIT_SUCCESS;
}
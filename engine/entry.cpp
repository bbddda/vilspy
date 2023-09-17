#include <Windows.h>

#include <fstream>
#include <iostream>
#include <logger.hpp>
#include <pe.hpp>
#include <string>

void InstallPayload(pe_c* pe, pe_c pyld) {
  pyld_ctx_t* ctx = (pyld_ctx_t*)pyld.FindExport("g_ctx");
  memset(ctx, 0, sizeof(pyld_ctx_t));

  auto pyld_sec = pe->InsertSection(".obf0", pyld.ImageSize(), r | w | x | c);

  /* ENVIRONMENT SETUP */

  g_logger->Log<logger_c::wait>(L"setting environment...");
  {
    ctx->key0 = time(nullptr) ^ GetTickCount64();
    ctx->key1 = ctx->key0 + __rdtsc();
    ctx->key2 = (ctx->key0 * ctx->key1) ^ pyld.ImageSize();
    ctx->ep = *pe->EntryPointVA();
  }

  /* BINARY PACKING */

  g_logger->Log<logger_c::wait>(L"packing binary...");
  {
    for (auto sec = pe->FirstSection(); sec < pe->LastSection(); ++sec) {
      if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE)) continue;

      section_t* ctx_sec = &ctx->sections[ctx->section_count++];

      ctx_sec->va = sec->VirtualAddress;
      ctx_sec->size = sec->Misc.VirtualSize;
      ctx_sec->crc_size = min(sec->SizeOfRawData, sec->Misc.VirtualSize);
      ctx_sec->crc_dec = 0;

      u64 start = pe->Base() + sec->PointerToRawData;
      
      /* Save CRC */
      for (u64 curr = start; curr < start + ctx_sec->crc_size; ++curr) {
        ctx_sec->crc_dec = _mm_crc32_u8(ctx_sec->crc_dec, *(u8*)curr);
      }

      /* Encryption */
      for (u64 curr = start; curr < start + sec->SizeOfRawData; ++curr) {
        u8* b = (u8*)curr;
        *b = enc8(*b, ctx->key0, ctx->key1, ctx->key2);
      }

      g_logger->Log(L"crc_dec: 0x%x", ctx_sec->crc_dec);
    }
  }

  /* PAYLOAD INJECTION */

  g_logger->Log<logger_c::wait>(L"setting payload...");
  {
    for (auto sec = pyld.FirstSection(); sec <= pyld.LastSection(); ++sec) {
      u32 size = max(sec->SizeOfRawData, sec->Misc.VirtualSize);
      u64 dst = pe->Base() + pyld_sec->PointerToRawData + sec->VirtualAddress;
      u64 src = pyld.Base() + sec->PointerToRawData;

      memcpy((void*)dst, (void*)src, size);
    }
  }

  /* ENTRYPOINT PATCH */

  g_logger->Log<logger_c::wait>(L"redirecting entry...");
  {
    u32 new_ep = pyld_sec->VirtualAddress + *pyld.EntryPointVA();
    *pe->EntryPointVA() = new_ep;
  }

  g_logger->Log(L"key0: 0x%llx", ctx->key0);
  g_logger->Log(L"key1: 0x%llx", ctx->key1);
  g_logger->Log(L"key2: 0x%llx", ctx->key2);
  g_logger->Log(L"ep: 0x%x", ctx->ep);
  g_logger->Log(L"section_count: %i", ctx->section_count);
}

s32 main(s32 argc, char* argv[]) {
  if (argc < 3) {
    g_logger->Log<logger_c::err>(L"rewriter.exe <input> <output>");
    return EXIT_FAILURE;
  }

  g_logger->Log<logger_c::wait>(L"loading file...");
  pe_c pe{argv[1]};

  g_logger->Log<logger_c::wait>(L"obfuscating binary...");
  InstallPayload(&pe, pe_c{"payload.dll"});

  g_logger->Log<logger_c::wait>(L"saving file...");
  pe.Save(argv[2]);

  return EXIT_SUCCESS;
}
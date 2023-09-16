#include <Windows.h>

#include <fstream>
#include <iostream>
#include <logger.hpp>
#include <pe.hpp>
#include <string>

void InstallPayload(pe_c* pe) {
  pe_c pyld{"payload.dll"};

  g_logger->Log<logger_c::wait>(L"setting environment...");
  pyld_ctx_t* g_ctx = (pyld_ctx_t*)pyld.FindExport("g_ctx");
  g_ctx->ep = *pe->EntryPointVA();

  g_logger->Log<logger_c::wait>(L"setting payload...");
  auto pyld_sec = pe->InsertSection(".obf", 0x10000, r | w | x | c);
  for (auto sec = pyld.FirstSection(); sec <= pyld.LastSection(); ++sec) {
    u32 size = max(sec->SizeOfRawData, sec->Misc.VirtualSize);
    u64 dst = pe->Base() + pyld_sec->PointerToRawData + sec->VirtualAddress;
    u64 src = pyld.Base() + sec->PointerToRawData;
    
    memcpy((void*)dst, (void*)src, size);
  }

  g_logger->Log<logger_c::wait>(L"redirecting entry...");
  *pe->EntryPointVA() = pyld_sec->VirtualAddress + *pyld.EntryPointVA();
}

s32 main(s32 argc, char* argv[]) {
  if (argc < 3) {
    g_logger->Log<logger_c::err>(L"rewriter.exe <input> <output>");
    return EXIT_FAILURE;
  }

  g_logger->Log<logger_c::wait>(L"loading file...");
  pe_c pe{argv[1]};

  g_logger->Log<logger_c::wait>(L"obfuscating binary...");
  InstallPayload(&pe);

  g_logger->Log<logger_c::wait>(L"saving file...");
  pe.Save(argv[2]);

  return EXIT_SUCCESS;
}
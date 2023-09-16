#pragma once

#include <vector>
#include <string>

#include <Windows.h>

constexpr u32 x = IMAGE_SCN_MEM_EXECUTE;
constexpr u32 r = IMAGE_SCN_MEM_READ;
constexpr u32 w = IMAGE_SCN_MEM_WRITE;
constexpr u32 c = IMAGE_SCN_CNT_CODE;

class pe_c {
 private:
  std::vector<u8> m_bytes;

 public:
  pe_c(const std::vector<u8>& bytes);
  pe_c(const std::string& filepath);
  ~pe_c();
  
  u64 FindExport(const char* name);

  u64 Base();
  u64 Size();

  IMAGE_DOS_HEADER* Dos();
  IMAGE_NT_HEADERS* Nt();

  u64 RvaToOffset(u64 rva);
  u64 AlignRaw(u64 addr);
  u64 AlignVirt(u64 addr);

  IMAGE_SECTION_HEADER* FirstSection();
  IMAGE_SECTION_HEADER* LastSection();
  IMAGE_SECTION_HEADER* InsertSection(const char* name, u32 size, u32 flags);
  IMAGE_SECTION_HEADER* FindSection(const char* name);
  u64 EntryPoint();
  u32* EntryPointVA();
  bool Save(const std::string& filepath);
};
#include <fstream>
#include <pe.hpp>

pe_c::pe_c(const std::vector<u8>& bytes) { m_bytes = bytes; }
pe_c::pe_c(const std::string& filepath) {
  std::ifstream input{filepath, std::ios::binary};
  m_bytes = {std::istreambuf_iterator<char>(input),
             std::istreambuf_iterator<char>()};
  input.close();
}
pe_c::~pe_c() {}

u64 pe_c::FindExport(const char* name) {
  auto dir = Nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  auto eat = (IMAGE_EXPORT_DIRECTORY*)(Base() + RvaToOffset(dir.VirtualAddress));

  u32* functions = (u32*)(Base() + RvaToOffset(eat->AddressOfFunctions));
  u32* names = (u32*)(Base() + RvaToOffset(eat->AddressOfNames));
  u16* ordinals = (u16*)(Base() + RvaToOffset(eat->AddressOfNameOrdinals));

  for (u32 i = 0; i < eat->NumberOfNames; ++i) {
    const char* exp_name = (const char*)(Base() + RvaToOffset(names[i]));
    if (!strcmp(exp_name, name)) {
      return Base() + RvaToOffset(functions[ordinals[i]]);
    }
  }

  return 0;
}

std::vector<u8>* pe_c::Bytes() { return &m_bytes; }

u64 pe_c::Base() { return (u64)m_bytes.data(); }

u64 pe_c::Size() { return m_bytes.size(); }

IMAGE_DOS_HEADER* pe_c::Dos() { return (IMAGE_DOS_HEADER*)Base(); }

IMAGE_NT_HEADERS* pe_c::Nt() {
  return (IMAGE_NT_HEADERS*)(Base() + Dos()->e_lfanew);
}

u64 pe_c::ImageSize() { return Nt()->OptionalHeader.SizeOfImage; }

u64 pe_c::RvaToOffset(u64 rva) {
  for (auto sec = FirstSection(); sec <= LastSection(); ++sec) {
    u32 start = sec->VirtualAddress;
    u32 end = sec->VirtualAddress + sec->Misc.VirtualSize;

    if (rva >= start && rva < end) {
      return (rva - sec->VirtualAddress) + sec->PointerToRawData;
    }
  }

  return 0;
}

u64 pe_c::AlignRaw(u64 addr) {
  u32 alignment = Nt()->OptionalHeader.FileAlignment;
  return ((addr + alignment - 1) & ~(alignment - 1));
}

u64 pe_c::AlignVirt(u64 addr) {
  u32 alignment = Nt()->OptionalHeader.SectionAlignment;
  return ((addr + alignment - 1) & ~(alignment - 1));
}

IMAGE_SECTION_HEADER* pe_c::FirstSection() { return IMAGE_FIRST_SECTION(Nt()); }

IMAGE_SECTION_HEADER* pe_c::LastSection() {
  return FirstSection() + (Nt()->FileHeader.NumberOfSections - 1);
}

IMAGE_SECTION_HEADER* pe_c::InsertSection(const char* name, u32 size,
                                          u32 flags) {
  u32 section_alignment = Nt()->OptionalHeader.SectionAlignment,
      file_alignment = Nt()->OptionalHeader.FileAlignment;

  u32 virtual_size = AlignVirt(size);
  u32 raw_size = AlignRaw(size);

  m_bytes.resize(m_bytes.size() + raw_size, 0);
  IMAGE_SECTION_HEADER* section = LastSection() + 1;
  strncpy((char*)section->Name, name, IMAGE_SIZEOF_SHORT_NAME - 1);
  section->Misc.VirtualSize = virtual_size;
  section->PointerToRawData =
      AlignRaw(LastSection()->PointerToRawData + LastSection()->SizeOfRawData);
  section->SizeOfRawData = raw_size;
  section->Characteristics = flags;
  section->VirtualAddress = AlignVirt(LastSection()->VirtualAddress +
                                      LastSection()->Misc.VirtualSize);
  Nt()->FileHeader.NumberOfSections++;
  Nt()->OptionalHeader.SizeOfImage =
      section->VirtualAddress + section->Misc.VirtualSize;

  return section;
}

IMAGE_SECTION_HEADER* pe_c::FindSection(const char* name) {
  for (auto sec = FirstSection(); sec <= LastSection(); ++sec) {
    if (!strcmp((char*)sec->Name, name)) {
      return sec;
    }
  }

  return nullptr;
}

u64 pe_c::EntryPoint() {
  return Base() + RvaToOffset(Nt()->OptionalHeader.AddressOfEntryPoint);
}

u32* pe_c::EntryPointVA() {
  return (u32*)&Nt()->OptionalHeader.AddressOfEntryPoint;
}

bool pe_c::Save(const std::string& filepath) {
  std::ofstream output{filepath, std::ios::binary};
  bool status = output.write((char*)Base(), m_bytes.size()).good();
  output.close();

  return status;
}
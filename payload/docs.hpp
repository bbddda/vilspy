#pragma once

#include <Windows.h>
#include <winternl.h>

#define CONTAINS_RECORD(address, type, field) \
  ((type*)((char*)(address) - (ULONGLONG)(&((type*)0)->field)))

typedef struct FULL_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderModuleList;
    void* DllBase;
    void* EntryPoint;
    union {
        ULONG SizeOfImage;
        const char* _dummy;
    };
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} FULL_LDR_DATA_TABLE_ENTRY, * PFULL_LDR_DATA_TABLE_ENTRY;


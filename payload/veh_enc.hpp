#pragma once

#include <Windows.h>
#include <types.hpp>
#include <iat.hpp>

namespace veh_enc {
inline u128 g_key;
inline u64 g_prev_page;
inline CRITICAL_SECTION g_critical;
inline decltype(&VirtualProtect) g_VirtualProtect;
inline decltype(&RtlEnterCriticalSection) g_RtlEnterCriticalSection;
inline decltype(&RtlLeaveCriticalSection) g_RtlLeaveCriticalSection;


void ProtectPage(uint64_t base);
void UnProtectPage(uint64_t base);

LONG NTAPI OnException(EXCEPTION_POINTERS* ctx);
void GuardPage(u64 base);
bool Install(u128 key);
}  // namespace veh_enc
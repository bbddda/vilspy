#include <iostream>
#include <logger.hpp>
#include <chrono>
#include <Windows.h>

void logger_c::PrintLog(logger_c* logger, code_e code,
                        const std::wstring& log) {
  if (code == no_prefix) {
    wprintf(L"%s\n", log.data());
    return;
  } 

  wchar_t prefix = ' ';
  switch (code) {
    case ok:
      prefix = L'+';
      break;
    case err:
      prefix = L'!';
      break;
    case warn:
      prefix = L'>';
      break;
  }

  if (code == wait) {
    u8 spin_idx = 0;

    constexpr wchar_t spinner[] = {'/', '-', '\\', '|'};
    constexpr u8 spins = sizeof(spinner) / sizeof(wchar_t);

    u64 last_tick = GetTickCount64();
    while (logger->m_logs.size() == 1 && !logger->m_exit) {
      u64 now = GetTickCount64();
      if (now < last_tick + 50) continue;

      wprintf(L"[%c] %s\r", spinner[spin_idx], log.data());
      spin_idx = spin_idx == spins - 1 ? 0 : spin_idx + 1;

      last_tick = now;
    }

    wprintf(L"[-] %s\n", log.data());
  } else {
    wprintf(L"[%c] %s\n", prefix, log.data());
  }
}

void logger_c::LogThread(logger_c* logger) {
  while (!logger->m_exit.load() || !logger->m_logs.empty()) {  // Fix here
    while (!logger->m_logs.empty()) {
      auto const& [code, content] = logger->m_logs.front();
      PrintLog(logger, code, content);
      logger->m_logs.pop();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

logger_c::logger_c() {
  m_exit.store(false);
  m_thread = std::thread(&LogThread, this);
}

logger_c::~logger_c() {
  m_exit.store(true);
  m_thread.join();
}

void logger_c::Log(code_e code, const std::wstring& content) {
  return m_logs.push({code, content});
}
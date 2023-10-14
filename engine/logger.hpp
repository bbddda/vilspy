#pragma once

#include <stdarg.h>
#include <Windows.h>
#include <queue>
#include <string>
#include <thread>

#include <types.hpp>

class logger_c {
 public:
  enum code_e : u8 { ok, err, wait, warn, no_prefix };

  std::atomic<bool> m_exit;
  std::thread m_thread;
  std::queue<std::pair<code_e, std::wstring>> m_logs;

  static void PrintLog(logger_c* logger, code_e code, const std::wstring& log);
  static void LogThread(logger_c* logger);

  logger_c();
  ~logger_c();

  void Log(code_e code, const std::wstring& content);

  template <code_e code = code_e::ok>
  void Log(const std::wstring& content, ...) {
    wchar_t buffer[256];

    va_list va;
    va_start(va, content.data());
    vswprintf_s(buffer, content.data(), va);
    va_end(va);

    return Log(code, buffer);
  }
};

inline std::unique_ptr<logger_c> g_logger = std::make_unique<logger_c>();
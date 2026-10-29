// Structured, scrubbed logging (owner: LNX, spec §11).
//
// One JSON object per line:
//   {"ts_ns":..., "level":"info", "component":"vault", "event":"store.ok", "fields":{...}}
// - component and event names are identifiers ([a-z][a-z0-9_.]{0,63}), never free text;
// - field names are identifiers too, and the banned names (value, raw, text_raw,
//   secret, plaintext) are dropped, counted in "dropped_fields";
// - every string field is truncated to kMaxLogString bytes and passed through scrub().
// Python twin: plpy.log.
#pragma once

#include <cstdint>
#include <functional>
#include <initializer_list>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace pl {

inline constexpr std::size_t kMaxLogString = 512;

enum class LogLevel : std::uint8_t { debug, info, warn, error };

using LogValue = std::variant<std::int64_t, double, bool, std::string>;
using LogField = std::pair<std::string_view, LogValue>;
using LogSink = std::function<void(std::string_view line)>;

[[nodiscard]] bool is_identifier(std::string_view s, std::size_t max_len) noexcept;
[[nodiscard]] bool is_banned_field(std::string_view name) noexcept;

class Logger {
 public:
  // Throws std::invalid_argument for a component name that isn't an identifier.
  explicit Logger(std::string component, LogSink sink = stderr_sink(), LogLevel min_level = LogLevel::info);

  void log(LogLevel level, std::string_view event, std::initializer_list<LogField> fields = {});
  void debug(std::string_view event, std::initializer_list<LogField> f = {}) { log(LogLevel::debug, event, f); }
  void info(std::string_view event, std::initializer_list<LogField> f = {}) { log(LogLevel::info, event, f); }
  void warn(std::string_view event, std::initializer_list<LogField> f = {}) { log(LogLevel::warn, event, f); }
  void error(std::string_view event, std::initializer_list<LogField> f = {}) { log(LogLevel::error, event, f); }

  // Formats a line without writing it (used by tests and by log forwarding).
  [[nodiscard]] std::string format(LogLevel level, std::string_view event, std::initializer_list<LogField> fields,
                                   std::uint64_t ts_ns) const;

  [[nodiscard]] static LogSink stderr_sink();

 private:
  std::string component_;
  LogSink sink_;
  LogLevel min_level_;
  std::mutex mu_;
};

}  // namespace pl

#include "pl/log.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "pl/ids.hpp"
#include "pl/scrub.hpp"

namespace pl {

namespace {

constexpr std::array<std::string_view, 4> kLevelNames = {"debug", "info", "warn", "error"};
constexpr std::array<std::string_view, 5> kBanned = {"value", "raw", "text_raw", "secret", "plaintext"};
constexpr std::size_t kMaxEventName = 64;
constexpr std::size_t kMaxFieldName = 32;

// Truncate on a UTF-8 boundary so the JSON encoder never sees a split sequence.
std::string_view truncate_utf8(std::string_view s, std::size_t max) noexcept {
  if (s.size() <= max) {
    return s;
  }
  std::size_t n = max;
  while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0U) == 0x80U) {
    --n;
  }
  return s.substr(0, n);
}

}  // namespace

bool is_identifier(std::string_view s, std::size_t max_len) noexcept {
  if (s.empty() || s.size() > max_len || s[0] < 'a' || s[0] > 'z') {
    return false;
  }
  return std::ranges::all_of(s, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.'; });
}

bool is_banned_field(std::string_view name) noexcept {
  return std::ranges::any_of(kBanned, [name](std::string_view b) { return name == b; });
}

Logger::Logger(std::string component, LogSink sink, LogLevel min_level)
    : component_(std::move(component)), sink_(std::move(sink)), min_level_(min_level) {
  if (!is_identifier(component_, kMaxFieldName)) {
    throw std::invalid_argument("logger component must be an identifier");
  }
}

std::string Logger::format(LogLevel level, std::string_view event, std::initializer_list<LogField> fields,
                           std::uint64_t ts_ns) const {
  nlohmann::json line = {{"ts_ns", ts_ns},
                         {"level", kLevelNames.at(static_cast<std::size_t>(level))},
                         {"component", component_},
                         {"event", is_identifier(event, kMaxEventName) ? std::string(event) : std::string("invalid_event_name")}};
  nlohmann::json out_fields = nlohmann::json::object();
  std::int64_t dropped = 0;
  for (const auto& [name, val] : fields) {
    if (!is_identifier(name, kMaxFieldName) || is_banned_field(name) || name.find('.') != std::string_view::npos) {
      ++dropped;
      continue;
    }
    const std::string key(name);
    std::visit(
        [&](const auto& v) {
          using T = std::decay_t<decltype(v)>;
          if constexpr (std::is_same_v<T, std::string>) {
            out_fields[key] = scrub(truncate_utf8(v, kMaxLogString));
          } else {
            out_fields[key] = v;
          }
        },
        val);
  }
  line["fields"] = std::move(out_fields);
  if (dropped > 0) {
    line["dropped_fields"] = dropped;
  }
  return line.dump(-1, ' ', /*ensure_ascii=*/true, nlohmann::json::error_handler_t::replace);
}

void Logger::log(LogLevel level, std::string_view event, std::initializer_list<LogField> fields) {
  if (level < min_level_) {
    return;
  }
  const std::string line = format(level, event, fields, realtime_ns());
  const std::lock_guard lock(mu_);
  sink_(line);
}

LogSink Logger::stderr_sink() {
  return [](std::string_view line) {
    std::string buf(line);
    buf.push_back('\n');
    std::size_t off = 0;
    while (off < buf.size()) {
      const ssize_t n = ::write(STDERR_FILENO, buf.data() + off, buf.size() - off);
      if (n <= 0) {
        return;  // never throw from logging
      }
      off += static_cast<std::size_t>(n);
    }
  };
}

}  // namespace pl

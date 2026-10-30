#include "pl/detect/normalize.hpp"

#include <array>
#include <utility>

namespace pl::detect {
namespace {

// Decode one UTF-8 code point at s[i]; invalid sequences decode as U+FFFD, length 1.
std::pair<char32_t, std::size_t> decode(std::string_view s, std::size_t i) {
  const auto b0 = static_cast<unsigned char>(s[i]);
  if (b0 < 0x80U) {
    return {static_cast<char32_t>(b0), 1};
  }
  std::size_t len = 0;
  char32_t cp = 0;
  if ((b0 & 0xE0U) == 0xC0U) {
    len = 2;
    cp = b0 & 0x1FU;
  } else if ((b0 & 0xF0U) == 0xE0U) {
    len = 3;
    cp = b0 & 0x0FU;
  } else if ((b0 & 0xF8U) == 0xF0U) {
    len = 4;
    cp = b0 & 0x07U;
  } else {
    return {U'�', 1};
  }
  if (i + len > s.size()) {
    return {U'�', 1};
  }
  for (std::size_t k = 1; k < len; ++k) {
    const auto b = static_cast<unsigned char>(s[i + k]);
    if ((b & 0xC0U) != 0x80U) {
      return {U'�', 1};
    }
    cp = (cp << 6U) | (b & 0x3FU);
  }
  return {cp, len};
}

void encode(char32_t cp, std::string& out) {
  if (cp < 0x80U) {
    out.push_back(static_cast<char>(cp));
  } else if (cp < 0x800U) {
    out.push_back(static_cast<char>(0xC0U | (cp >> 6U)));
    out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
  } else if (cp < 0x10000U) {
    out.push_back(static_cast<char>(0xE0U | (cp >> 12U)));
    out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
  } else {
    out.push_back(static_cast<char>(0xF0U | (cp >> 18U)));
    out.push_back(static_cast<char>(0x80U | ((cp >> 12U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
  }
}

struct Pair {
  char32_t from;
  char to;
};

// Cyrillic and Greek letters that look like Latin ones.
constexpr std::array<Pair, 36> kConfusables{{
    {0x0410, 'A'}, {0x0412, 'B'}, {0x0421, 'C'}, {0x0415, 'E'}, {0x041D, 'H'}, {0x041A, 'K'}, {0x041C, 'M'},
    {0x041E, 'O'}, {0x0420, 'P'}, {0x0422, 'T'}, {0x0425, 'X'}, {0x0430, 'a'}, {0x0441, 'c'}, {0x0435, 'e'},
    {0x043E, 'o'}, {0x0440, 'p'}, {0x0445, 'x'}, {0x0443, 'y'}, {0x0456, 'i'}, {0x0458, 'j'}, {0x0455, 's'},
    {0x0391, 'A'}, {0x0392, 'B'}, {0x0395, 'E'}, {0x0397, 'H'}, {0x0399, 'I'}, {0x039A, 'K'}, {0x039C, 'M'},
    {0x039D, 'N'}, {0x039F, 'O'}, {0x03A1, 'P'}, {0x03A4, 'T'}, {0x03A7, 'X'}, {0x03BF, 'o'}, {0x0501, 'd'},
    {0x051B, 'q'},
}};

// First code point of each decimal digit block we map to ASCII digits.
constexpr std::array<char32_t, 12> kDigitZeros{
    0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66,
};

// Returns the replacement (0 = drop, U+FFFF = keep as is).
char32_t map(char32_t cp) {
  if (is_invisible(cp)) {
    return 0;
  }
  if (cp >= 0xFF01U && cp <= 0xFF5EU) {  // full-width ASCII
    return cp - 0xFEE0U;
  }
  if (cp == 0x00A0U || (cp >= 0x2000U && cp <= 0x200AU) || cp == 0x202FU || cp == 0x205FU || cp == 0x3000U) {
    return U' ';
  }
  if (cp == 0x2010U || cp == 0x2011U || cp == 0x2012U || cp == 0x2013U || cp == 0x2212U) {
    return U'-';
  }
  for (const char32_t z : kDigitZeros) {
    if (cp >= z && cp <= z + 9U) {
      return U'0' + (cp - z);
    }
  }
  for (const auto& p : kConfusables) {
    if (p.from == cp) {
      return static_cast<char32_t>(static_cast<unsigned char>(p.to));
    }
  }
  return 0xFFFFU;
}

}  // namespace

bool is_invisible(char32_t cp) noexcept {
  return cp == 0x00ADU || cp == 0x034FU || cp == 0x061CU || cp == 0x180EU || (cp >= 0x200BU && cp <= 0x200FU) ||
         (cp >= 0x202AU && cp <= 0x202EU) || (cp >= 0x2060U && cp <= 0x206FU) || cp == 0xFEFFU;
}

Normalized normalize(std::string_view utf8) {
  Normalized n;
  n.text.reserve(utf8.size());
  n.begin.reserve(utf8.size());
  n.end.reserve(utf8.size());
  std::size_t i = 0;
  while (i < utf8.size()) {
    const auto [cp, len] = decode(utf8, i);
    const char32_t r = map(cp);
    const std::size_t before = n.text.size();
    if (r == 0xFFFFU) {
      n.text.append(utf8.substr(i, len));
    } else if (r != 0) {
      encode(r, n.text);
    }
    for (std::size_t k = before; k < n.text.size(); ++k) {
      n.begin.push_back(static_cast<std::uint32_t>(i));
      n.end.push_back(static_cast<std::uint32_t>(i + len));
    }
    i += len;
  }
  return n;
}

}  // namespace pl::detect

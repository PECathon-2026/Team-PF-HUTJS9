#include "ledger/segment.hpp"

#include <fcntl.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <system_error>

namespace pl::ledger {

namespace fs = std::filesystem;

std::string sha256_hex(std::string_view data) {
  if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
  unsigned char out[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(out, reinterpret_cast<const unsigned char*>(data.data()), data.size());
  char hex[crypto_hash_sha256_BYTES * 2 + 1];
  sodium_bin2hex(hex, sizeof hex, out, sizeof out);
  return std::string(hex);
}

namespace {

std::string segment_name(std::uint64_t index) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "seg-%08llu.jsonl", static_cast<unsigned long long>(index));
  return buf;
}

std::vector<fs::path> list_segments(const fs::path& dir) {
  std::vector<fs::path> out;
  if (!fs::exists(dir)) return out;
  for (const auto& e : fs::directory_iterator(dir)) {
    const auto name = e.path().filename().string();
    if (name.size() == 18 && name.rfind("seg-", 0) == 0 && name.ends_with(".jsonl")) out.push_back(e.path());
  }
  std::sort(out.begin(), out.end());
  return out;
}

std::uint64_t index_of(const fs::path& p) { return std::stoull(p.filename().string().substr(4, 8)); }

void write_all(int fd, std::string_view data) {
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      throw std::system_error(errno, std::generic_category(), "ledger segment write");
    }
    off += static_cast<std::size_t>(n);
  }
}

}  // namespace

SegmentWriter::SegmentWriter(SegmentConfig cfg) : cfg_(std::move(cfg)) {
  fs::create_directories(cfg_.dir);
  const auto segs = list_segments(cfg_.dir);
  if (segs.empty()) {
    open_segment(1);
    return;
  }
  // Recover from the last segment: find the last complete line.
  const fs::path last = segs.back();
  std::string content;
  {
    std::ifstream in(last, std::ios::binary);
    content.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  }
  const auto nl = content.rfind('\n');
  const std::size_t good = nl == std::string::npos ? 0 : nl + 1;
  if (good != content.size()) {
    // Torn tail: never acknowledged, so dropping it loses nothing that a producer was told was stored.
    fs::permissions(last, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::add);
    if (::truncate(last.c_str(), static_cast<off_t>(good)) != 0) {
      throw std::system_error(errno, std::generic_category(), "truncate torn tail");
    }
    content.resize(good);
  }
  if (good == 0) {
    // Empty last segment: chain head comes from the previous segment if any.
    if (segs.size() > 1) {
      std::ifstream in(segs[segs.size() - 2], std::ios::binary);
      std::string line, prev;
      while (std::getline(in, line)) prev = line;
      if (!prev.empty()) {
        head_ = sha256_hex(prev);
        next_seq_ = nlohmann::json::parse(prev).at("seq").get<std::uint64_t>() + 1;
      }
    }
  } else {
    const auto start = content.rfind('\n', good - 2);
    const std::string line = content.substr(start == std::string::npos ? 0 : start + 1,
                                            good - 1 - (start == std::string::npos ? 0 : start + 1));
    head_ = sha256_hex(line);
    next_seq_ = nlohmann::json::parse(line).at("seq").get<std::uint64_t>() + 1;
  }
  index_ = index_of(last);
  size_ = content.size();
  fs::permissions(last, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::add);
  fd_ = Fd(::open(last.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC));
  if (!fd_.valid()) throw std::system_error(errno, std::generic_category(), "open segment");
}

void SegmentWriter::open_segment(std::uint64_t index) {
  const fs::path p = cfg_.dir / segment_name(index);
  fd_ = Fd(::open(p.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC, 0640));
  if (!fd_.valid()) throw std::system_error(errno, std::generic_category(), "create segment");
  index_ = index;
  size_ = 0;
}

void SegmentWriter::seal_current() {
  if (!fd_.valid()) return;
  ::fdatasync(fd_.get());
  ::fchmod(fd_.get(), 0440);
  fd_.reset();
}

std::string SegmentWriter::append(std::string_view kind, const nlohmann::json& record, std::uint64_t ts_ns,
                                  std::uint64_t* seq_out) {
  nlohmann::json entry = {{"kind", kind}, {"prev", head_}, {"record", record}, {"seq", next_seq_}, {"ts_ns", ts_ns}};
  const std::string line = entry.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
  if (size_ > 0 && size_ + line.size() + 1 > cfg_.max_segment_bytes) {
    seal_current();
    open_segment(index_ + 1);
  }
  write_all(fd_.get(), line + "\n");
  if (cfg_.sync && ::fdatasync(fd_.get()) != 0) throw std::system_error(errno, std::generic_category(), "fdatasync");
  size_ += line.size() + 1;
  if (seq_out != nullptr) *seq_out = next_seq_;
  ++next_seq_;
  head_ = sha256_hex(line);
  return line;
}

std::vector<std::string> read_all_lines(const fs::path& dir) {
  std::vector<std::string> lines;
  for (const auto& seg : list_segments(dir)) {
    std::ifstream in(seg, std::ios::binary);
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);
  }
  return lines;
}

VerifyResult verify_segments(const fs::path& dir) {
  VerifyResult r;
  std::string prev(kZeroHash);
  std::uint64_t expect_seq = 1;
  for (const auto& seg : list_segments(dir)) {
    std::ifstream in(seg, std::ios::binary);
    std::string line;
    while (std::getline(in, line)) {
      nlohmann::json e = nlohmann::json::parse(line, nullptr, false);
      if (!e.is_object() || !e.contains("seq") || !e.contains("prev")) {
        r.error = "malformed entry after seq " + std::to_string(expect_seq - 1);
        return r;
      }
      if (e["seq"].get<std::uint64_t>() != expect_seq) {
        r.error = "sequence gap at seq " + std::to_string(expect_seq);
        return r;
      }
      if (e["prev"].get<std::string>() != prev) {
        r.error = "hash chain broken at seq " + std::to_string(expect_seq);
        return r;
      }
      prev = sha256_hex(line);
      ++expect_seq;
      ++r.entries;
    }
  }
  r.ok = true;
  return r;
}

}  // namespace pl::ledger

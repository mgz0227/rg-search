// rgs.cpp - Native A/B/C field searcher
// C++20 single-binary rewrite of rg-search for authorized local data review.
// No Python, no SQLite, no ripgrep subprocess in the default fast path.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

static constexpr const char* APP_VERSION = "5.0.2-native-cpp-console-visible";
static constexpr char KEY_SEP = '\x1f';

struct Args {
    bool help = false;
    bool self_test = false;
    bool interactive = false;
    bool gui = false;
    bool scan = false;
    std::vector<std::string> paths;
    std::vector<std::string> keywords;
    std::vector<std::string> keyword_files;
    std::string field = "B";          // ANY, A, B, C
    std::string format = "csv";       // csv, txt, jsonl
    std::string columns = "abc";      // abc, full
    std::string parse_mode = "urlpath"; // simple, url, urlpath
    std::string output = "rg_abc_results.csv";
    std::string summary = "";
    bool regex = false;
    bool ignore_case = false;
    bool dedupe = true;
    bool keep_matches = false;
    bool quiet = false;
    bool debug = false;
    bool no_summary = true;
    bool list_only = false;
    size_t limit = 0;
    size_t progress_every = 1000000;
    size_t max_filesize = 0;
    unsigned threads = 0;
    std::vector<std::string> include_globs;
    std::vector<std::string> exclude_globs;
};

struct Stats {
    std::atomic<uint64_t> files_seen{0};
    std::atomic<uint64_t> files_scanned{0};
    std::atomic<uint64_t> bytes_scanned{0};
    std::atomic<uint64_t> candidate_lines{0};
    std::atomic<uint64_t> parsed_triples{0};
    std::atomic<uint64_t> field_hits{0};
    std::atomic<uint64_t> written{0};
    std::atomic<uint64_t> duplicates{0};
    std::atomic<uint64_t> errors{0};
};

struct TripleView {
    std::string_view a;
    std::string_view b;
    std::string_view c;
};

static std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::ostringstream os;
    os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return os.str();
}

static std::string lower_ascii(std::string s) {
    for (char& ch : s) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (c >= 'A' && c <= 'Z') ch = static_cast<char>(c + 32);
    }
    return s;
}

static char lower_ascii_char(char ch) {
    unsigned char c = static_cast<unsigned char>(ch);
    if (c >= 'A' && c <= 'Z') return static_cast<char>(c + 32);
    return ch;
}

static std::string trim_copy(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) sv.remove_prefix(1);
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) sv.remove_suffix(1);
    return std::string(sv);
}

static std::string_view trim_view(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) sv.remove_prefix(1);
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) sv.remove_suffix(1);
    return sv;
}

static bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (lower_ascii_char(a[i]) != lower_ascii_char(b[i])) return false;
    }
    return true;
}

static bool starts_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.substr(0, p.size()) == p;
}

static bool contains_icase_ascii(std::string_view hay, std::string_view needle_lower) {
    if (needle_lower.empty()) return true;
    if (needle_lower.size() > hay.size()) return false;
    const size_t n = needle_lower.size();
    const char first = needle_lower[0];
    for (size_t i = 0; i + n <= hay.size(); ++i) {
        if (lower_ascii_char(hay[i]) != first) continue;
        size_t j = 1;
        for (; j < n; ++j) {
            if (lower_ascii_char(hay[i + j]) != needle_lower[j]) break;
        }
        if (j == n) return true;
    }
    return false;
}

static bool contains_any_fixed(std::string_view hay, const std::vector<std::string>& needles, bool ignore_case) {
    if (needles.empty()) return true;
    if (!ignore_case) {
        for (const auto& n : needles) {
            if (!n.empty() && hay.find(n) != std::string_view::npos) return true;
        }
        return false;
    }
    for (const auto& n : needles) {
        if (!n.empty() && contains_icase_ascii(hay, n)) return true;
    }
    return false;
}

static bool wildcard_match_impl(std::string_view pat, std::string_view str, bool ignore_case) {
    size_t p = 0, s = 0, star = std::string_view::npos, match = 0;
    auto eq = [ignore_case](char a, char b) {
        return ignore_case ? lower_ascii_char(a) == lower_ascii_char(b) : a == b;
    };
    while (s < str.size()) {
        if (p < pat.size() && (pat[p] == '?' || eq(pat[p], str[s]))) {
            ++p; ++s;
        } else if (p < pat.size() && pat[p] == '*') {
            star = p++;
            match = s;
        } else if (star != std::string_view::npos) {
            p = star + 1;
            s = ++match;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == '*') ++p;
    return p == pat.size();
}

static bool wildcard_match_any(const std::vector<std::string>& patterns, const fs::path& p) {
    if (patterns.empty()) return true;
    std::string full = p.generic_string();
    std::string name = p.filename().generic_string();
    for (const auto& pat : patterns) {
        if (wildcard_match_impl(pat, full, false) || wildcard_match_impl(pat, name, false)) return true;
    }
    return false;
}

static bool wildcard_excluded(const std::vector<std::string>& patterns, const fs::path& p) {
    if (patterns.empty()) return false;
    std::string full = p.generic_string();
    std::string name = p.filename().generic_string();
    for (const auto& pat : patterns) {
        if (wildcard_match_impl(pat, full, false) || wildcard_match_impl(pat, name, false)) return true;
        // A bare directory/file name exclude also works by substring on normalized path.
        if (pat.find('*') == std::string::npos && pat.find('?') == std::string::npos) {
            if (full.find(pat) != std::string::npos) return true;
        }
    }
    return false;
}

static std::vector<std::string> split_list(const std::string& text, char delim) {
    std::vector<std::string> out;
    std::string item;
    std::istringstream is(text);
    while (std::getline(is, item, delim)) {
        item = trim_copy(item);
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

static std::vector<std::string> load_keywords_from_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::vector<std::string> out;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        line = trim_copy(line);
        if (!line.empty() && line[0] != '#') out.push_back(line);
    }
    return out;
}

static size_t parse_size(std::string text) {
    text = trim_copy(text);
    if (text.empty()) return 0;
    char suffix = 0;
    if (!std::isdigit(static_cast<unsigned char>(text.back()))) {
        suffix = static_cast<char>(std::toupper(static_cast<unsigned char>(text.back())));
        text.pop_back();
    }
    double value = 0;
    try { value = std::stod(text); } catch (...) { return 0; }
    double mult = 1.0;
    if (suffix == 'K') mult = 1024.0;
    else if (suffix == 'M') mult = 1024.0 * 1024.0;
    else if (suffix == 'G') mult = 1024.0 * 1024.0 * 1024.0;
    return static_cast<size_t>(value * mult);
}

static std::string csv_escape(std::string_view v) {
    bool quote = false;
    for (char ch : v) {
        if (ch == ',' || ch == '"' || ch == '\n' || ch == '\r') { quote = true; break; }
    }
    if (!quote) return std::string(v);
    std::string out;
    out.reserve(v.size() + 4);
    out.push_back('"');
    for (char ch : v) {
        if (ch == '"') out += "\"\"";
        else out.push_back(ch);
    }
    out.push_back('"');
    return out;
}

static std::string json_escape(std::string_view v) {
    std::string out;
    out.reserve(v.size() + 8);
    for (unsigned char c : v) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

static std::string sanitize_txt(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (char ch : v) {
        if (ch == '\n' || ch == '\r') out.push_back(' ');
        else out.push_back(ch);
    }
    return trim_copy(out);
}

static std::optional<TripleView> parse_simple(std::string_view line) {
    line = trim_view(line);
    size_t i = line.find(':');
    if (i == std::string_view::npos || i == 0) return std::nullopt;
    size_t j = line.find(':', i + 1);
    if (j == std::string_view::npos || j <= i + 1) return std::nullopt;
    auto a = trim_view(line.substr(0, i));
    auto b = trim_view(line.substr(i + 1, j - i - 1));
    auto c = trim_view(line.substr(j + 1));
    if (a.empty() || b.empty()) return std::nullopt;
    return TripleView{a, b, c};
}

static std::optional<TripleView> parse_url(std::string_view line) {
    line = trim_view(line);
    if (line.empty()) return std::nullopt;
    size_t scheme = line.find("://");
    if (scheme == std::string_view::npos || scheme == 0) return parse_simple(line);
    size_t scan_start = scheme + 3;
    size_t pathish = std::string_view::npos;
    for (char marker : {'/', '?', '#'}) {
        size_t pos = line.find(marker, scan_start);
        if (pos != std::string_view::npos && (pathish == std::string_view::npos || pos < pathish)) pathish = pos;
    }
    if (pathish != std::string_view::npos) {
        size_t sep = line.find(':', pathish);
        if (sep != std::string_view::npos) {
            size_t next = line.find(':', sep + 1);
            if (next != std::string_view::npos && next > sep + 1) {
                auto a = trim_view(line.substr(0, sep));
                auto b = trim_view(line.substr(sep + 1, next - sep - 1));
                auto c = trim_view(line.substr(next + 1));
                if (!a.empty() && !b.empty()) return TripleView{a, b, c};
            }
        }
    }
    size_t sep = line.find(':', scan_start);
    if (sep == std::string_view::npos) return parse_simple(line);
    size_t next = line.find(':', sep + 1);
    if (next != std::string_view::npos && next > sep + 1) {
        bool port = true;
        for (size_t k = sep + 1; k < next; ++k) {
            if (!std::isdigit(static_cast<unsigned char>(line[k]))) { port = false; break; }
        }
        if (port) {
            sep = next;
            next = line.find(':', sep + 1);
        }
    }
    if (next == std::string_view::npos || next <= sep + 1) return parse_simple(line);
    auto a = trim_view(line.substr(0, sep));
    auto b = trim_view(line.substr(sep + 1, next - sep - 1));
    auto c = trim_view(line.substr(next + 1));
    if (a.empty() || b.empty()) return parse_simple(line);
    return TripleView{a, b, c};
}

static std::optional<TripleView> parse_urlpath(std::string_view line) {
    line = trim_view(line);
    size_t scheme = line.find("://");
    if (scheme != std::string_view::npos && scheme > 0) {
        size_t slash = line.find('/', scheme + 3);
        if (slash != std::string_view::npos) {
            size_t sep = line.find(':', slash);
            if (sep != std::string_view::npos) {
                size_t next = line.find(':', sep + 1);
                if (next != std::string_view::npos && next > sep + 1) {
                    auto a = trim_view(line.substr(0, sep));
                    auto b = trim_view(line.substr(sep + 1, next - sep - 1));
                    auto c = trim_view(line.substr(next + 1));
                    if (!a.empty() && !b.empty()) return TripleView{a, b, c};
                }
            }
        }
    }
    return parse_url(line);
}

static std::optional<TripleView> parse_triple(std::string_view line, const std::string& mode) {
    if (mode == "simple") return parse_simple(line);
    if (mode == "url") return parse_url(line);
    return parse_urlpath(line);
}

class MappedFile {
public:
    MappedFile() = default;
    ~MappedFile() { close(); }
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    bool open_file(const fs::path& path) {
        close();
#ifdef _WIN32
        file_ = CreateFileW(path.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(file_, &sz) || sz.QuadPart <= 0) return false;
        size_ = static_cast<size_t>(sz.QuadPart);
        mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping_) return false;
        data_ = static_cast<const char*>(MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0));
        return data_ != nullptr;
#else
        fd_ = ::open(path.c_str(), O_RDONLY);
        if (fd_ < 0) return false;
        struct stat st{};
        if (::fstat(fd_, &st) != 0 || st.st_size <= 0) return false;
        size_ = static_cast<size_t>(st.st_size);
        void* p = ::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
        if (p == MAP_FAILED) {
            data_ = nullptr;
            return false;
        }
        data_ = static_cast<const char*>(p);
        return true;
#endif
    }

    const char* data() const { return data_; }
    size_t size() const { return size_; }

    void close() {
#ifdef _WIN32
        if (data_) { UnmapViewOfFile(data_); data_ = nullptr; }
        if (mapping_) { CloseHandle(mapping_); mapping_ = nullptr; }
        if (file_ != INVALID_HANDLE_VALUE) { CloseHandle(file_); file_ = INVALID_HANDLE_VALUE; }
#else
        if (data_) { ::munmap(const_cast<char*>(data_), size_); data_ = nullptr; }
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
#endif
        size_ = 0;
    }
private:
    const char* data_ = nullptr;
    size_t size_ = 0;
#ifdef _WIN32
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
#else
    int fd_ = -1;
#endif
};

class Writer {
public:
    explicit Writer(const Args& args) : args_(args) {}

    bool open() {
        fs::path out(args_.output);
        if (!out.parent_path().empty()) {
            std::error_code ec;
            fs::create_directories(out.parent_path(), ec);
        }
        fp_.open(args_.output, std::ios::binary | std::ios::trunc);
        if (!fp_) return false;
        if (args_.format == "csv") {
            fp_ << "\xEF\xBB\xBF";
            if (args_.columns == "full") fp_ << "A,B,C,file,line,source_line,matches\n";
            else fp_ << "A,B,C\n";
        }
        return true;
    }

    void write(const TripleView& t, const std::string& file, uint64_t line_no, std::string_view source_line, const std::string& matches) {
        if (args_.format == "csv") {
            if (args_.columns == "full") {
                fp_ << csv_escape(t.a) << ',' << csv_escape(t.b) << ',' << csv_escape(t.c) << ','
                    << csv_escape(file) << ',' << line_no << ',' << csv_escape(source_line) << ',' << csv_escape(matches) << '\n';
            } else {
                fp_ << csv_escape(t.a) << ',' << csv_escape(t.b) << ',' << csv_escape(t.c) << '\n';
            }
        } else if (args_.format == "txt") {
            fp_ << sanitize_txt(t.a) << ':' << sanitize_txt(t.b) << ':' << sanitize_txt(t.c) << '\n';
        } else if (args_.format == "jsonl") {
            if (args_.columns == "full") {
                fp_ << "{\"A\":\"" << json_escape(t.a) << "\",\"B\":\"" << json_escape(t.b)
                    << "\",\"C\":\"" << json_escape(t.c) << "\",\"file\":\"" << json_escape(file)
                    << "\",\"line\":" << line_no << ",\"source_line\":\"" << json_escape(source_line)
                    << "\",\"matches\":\"" << json_escape(matches) << "\"}\n";
            } else {
                fp_ << "{\"A\":\"" << json_escape(t.a) << "\",\"B\":\"" << json_escape(t.b)
                    << "\",\"C\":\"" << json_escape(t.c) << "\"}\n";
            }
        } else {
            fp_ << sanitize_txt(t.a) << ':' << sanitize_txt(t.b) << ':' << sanitize_txt(t.c) << '\n';
        }
    }

    bool good() const { return static_cast<bool>(fp_); }
    void flush() { fp_.flush(); }
private:
    const Args& args_;
    std::ofstream fp_;
};

class Matcher {
public:
    explicit Matcher(const Args& args) : args_(args) {
        fixed_ = args.keywords;
        if (args.ignore_case) {
            for (auto& k : fixed_) k = lower_ascii(k);
        }
        if (args.regex) {
            auto flags = std::regex::ECMAScript;
            if (args.ignore_case) flags |= std::regex::icase;
            for (const auto& k : args.keywords) regexes_.emplace_back(k, flags);
        }
    }

    bool line_candidate(std::string_view line) const {
        if (args_.regex) return true;
        return contains_any_fixed(line, fixed_, args_.ignore_case);
    }

    bool field_matches(const TripleView& t, std::string* matches) const {
        if (args_.regex) return regex_match_fields(t, matches);
        return fixed_match_fields(t, matches);
    }
private:
    std::vector<std::string_view> selected_fields(const TripleView& t) const {
        if (iequals_ascii(args_.field, "A")) return {t.a};
        if (iequals_ascii(args_.field, "B")) return {t.b};
        if (iequals_ascii(args_.field, "C")) return {t.c};
        return {t.a, t.b, t.c};
    }

    bool fixed_match_fields(const TripleView& t, std::string* matches) const {
        auto fields = selected_fields(t);
        bool any = false;
        if (args_.keep_matches && matches) matches->clear();
        for (size_t i = 0; i < fixed_.size(); ++i) {
            const auto& needle = fixed_[i];
            bool hit = false;
            for (auto f : fields) {
                if (!args_.ignore_case) {
                    if (f.find(needle) != std::string_view::npos) { hit = true; break; }
                } else {
                    if (contains_icase_ascii(f, needle)) { hit = true; break; }
                }
            }
            if (hit) {
                any = true;
                if (args_.keep_matches && matches) {
                    if (!matches->empty()) matches->push_back(';');
                    matches->append(args_.keywords[i]);
                } else {
                    return true;
                }
            }
        }
        return any;
    }

    bool regex_match_fields(const TripleView& t, std::string* matches) const {
        auto fields = selected_fields(t);
        bool any = false;
        if (args_.keep_matches && matches) matches->clear();
        for (size_t i = 0; i < regexes_.size(); ++i) {
            bool hit = false;
            for (auto f : fields) {
                if (std::regex_search(f.begin(), f.end(), regexes_[i])) { hit = true; break; }
            }
            if (hit) {
                any = true;
                if (args_.keep_matches && matches) {
                    if (!matches->empty()) matches->push_back(';');
                    matches->append(args_.keywords[i]);
                } else {
                    return true;
                }
            }
        }
        return any;
    }

    const Args& args_;
    std::vector<std::string> fixed_;
    std::vector<std::regex> regexes_;
};

class Scanner {
public:
    explicit Scanner(Args args) : args_(std::move(args)), matcher_(args_) {}

    bool run(Stats& stats, std::string* error_message = nullptr) {
        start_ = std::chrono::steady_clock::now();
        if (args_.threads == 0) args_.threads = std::max(1u, std::thread::hardware_concurrency());
        if (!validate(error_message)) return false;
        std::vector<fs::path> files = collect_files(stats);
        if (files.empty()) {
            if (error_message) *error_message = "No input files matched the filters.";
            return false;
        }
        Writer writer(args_);
        if (!writer.open()) {
            if (error_message) *error_message = "Cannot open output file: " + args_.output;
            return false;
        }
        writer_ = &writer;
        std::atomic<size_t> index{0};
        unsigned nthreads = std::min<unsigned>(args_.threads, static_cast<unsigned>(files.size()));
        std::vector<std::thread> workers;
        for (unsigned i = 0; i < nthreads; ++i) {
            workers.emplace_back([&, i]() {
                while (true) {
                    if (stop_.load(std::memory_order_relaxed)) break;
                    size_t pos = index.fetch_add(1, std::memory_order_relaxed);
                    if (pos >= files.size()) break;
                    scan_file(files[pos], stats);
                }
            });
        }
        for (auto& t : workers) t.join();
        writer.flush();
        write_summary(stats, files.size());
        return true;
    }

    double elapsed_seconds() const {
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double> d = end - start_;
        return d.count();
    }

private:
    bool validate(std::string* err) {
        if (args_.paths.empty()) { if (err) *err = "No path provided."; return false; }
        if (args_.keywords.empty()) { if (err) *err = "No keyword provided."; return false; }
        std::string f = lower_ascii(args_.field);
        if (!(f == "any" || f == "a" || f == "b" || f == "c")) { if (err) *err = "field must be ANY/A/B/C"; return false; }
        std::string fmt = lower_ascii(args_.format);
        if (!(fmt == "csv" || fmt == "txt" || fmt == "jsonl")) { if (err) *err = "format must be csv/txt/jsonl"; return false; }
        std::string cols = lower_ascii(args_.columns);
        if (!(cols == "abc" || cols == "full")) { if (err) *err = "columns must be abc/full"; return false; }
        std::string pm = lower_ascii(args_.parse_mode);
        if (!(pm == "simple" || pm == "url" || pm == "urlpath")) { if (err) *err = "parse mode must be simple/url/urlpath"; return false; }
        args_.field = std::string(f.begin(), f.end());
        std::transform(args_.field.begin(), args_.field.end(), args_.field.begin(), [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
        args_.format = fmt;
        args_.columns = cols;
        args_.parse_mode = pm;
        return true;
    }

    std::vector<fs::path> collect_files(Stats& stats) {
        std::vector<fs::path> files;
        for (const auto& raw : args_.paths) {
            std::error_code ec;
            fs::path root(raw);
            if (!fs::exists(root, ec)) continue;
            if (fs::is_regular_file(root, ec)) {
                add_file(root, files, stats);
            } else if (fs::is_directory(root, ec)) {
                fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
                while (it != end) {
                    const fs::path p = it->path();
                    std::error_code ec2;
                    if (it->is_directory(ec2)) {
                        if (wildcard_excluded(args_.exclude_globs, p)) it.disable_recursion_pending();
                    } else if (it->is_regular_file(ec2)) {
                        add_file(p, files, stats);
                    }
                    it.increment(ec);
                }
            }
        }
        return files;
    }

    void add_file(const fs::path& p, std::vector<fs::path>& files, Stats& stats) {
        stats.files_seen.fetch_add(1, std::memory_order_relaxed);
        if (!wildcard_match_any(args_.include_globs, p)) return;
        if (wildcard_excluded(args_.exclude_globs, p)) return;
        if (args_.max_filesize > 0) {
            std::error_code ec;
            auto sz = fs::file_size(p, ec);
            if (!ec && sz > args_.max_filesize) return;
        }
        files.push_back(p);
    }

    void scan_file(const fs::path& path, Stats& stats) {
        MappedFile mf;
        if (!mf.open_file(path)) { stats.errors.fetch_add(1, std::memory_order_relaxed); return; }
        stats.files_scanned.fetch_add(1, std::memory_order_relaxed);
        stats.bytes_scanned.fetch_add(static_cast<uint64_t>(mf.size()), std::memory_order_relaxed);
        const char* base = mf.data();
        size_t size = mf.size();
        size_t pos = 0;
        uint64_t line_no = 1;
        std::string file_string;
        if (args_.columns == "full") file_string = path.generic_string();
        while (pos < size && !stop_.load(std::memory_order_relaxed)) {
            const char* start = base + pos;
            const void* nlptr = std::memchr(start, '\n', size - pos);
            size_t len;
            if (nlptr) len = static_cast<const char*>(nlptr) - start;
            else len = size - pos;
            if (len > 0 && start[len - 1] == '\r') --len;
            std::string_view line(start, len);
            process_line(line, file_string, line_no, stats);
            if (args_.limit > 0 && stats.written.load(std::memory_order_relaxed) >= args_.limit) {
                stop_.store(true, std::memory_order_relaxed);
                break;
            }
            if (!nlptr) break;
            pos = (static_cast<const char*>(nlptr) - base) + 1;
            ++line_no;
        }
    }

    void process_line(std::string_view line, const std::string& file_string, uint64_t line_no, Stats& stats) {
        if (!matcher_.line_candidate(line)) return;
        stats.candidate_lines.fetch_add(1, std::memory_order_relaxed);
        auto parsed = parse_triple(line, args_.parse_mode);
        if (!parsed) return;
        stats.parsed_triples.fetch_add(1, std::memory_order_relaxed);
        std::string matches;
        if (!matcher_.field_matches(*parsed, args_.keep_matches ? &matches : nullptr)) return;
        stats.field_hits.fetch_add(1, std::memory_order_relaxed);

        std::string key;
        if (args_.dedupe) {
            key.reserve(parsed->a.size() + parsed->b.size() + parsed->c.size() + 2);
            key.append(parsed->a);
            key.push_back(KEY_SEP);
            key.append(parsed->b);
            key.push_back(KEY_SEP);
            key.append(parsed->c);
        }

        std::lock_guard<std::mutex> lock(out_mutex_);
        if (args_.dedupe) {
            auto [_, inserted] = seen_.insert(std::move(key));
            if (!inserted) {
                stats.duplicates.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        if (args_.limit > 0 && stats.written.load(std::memory_order_relaxed) >= args_.limit) {
            stop_.store(true, std::memory_order_relaxed);
            return;
        }
        writer_->write(*parsed, file_string, line_no, line, matches);
        uint64_t w = stats.written.fetch_add(1, std::memory_order_relaxed) + 1;
        if (!args_.quiet && args_.progress_every > 0 && w % args_.progress_every == 0) {
            const double e = elapsed_seconds();
            std::cerr << "progress written=" << w
                      << " candidate=" << stats.candidate_lines.load()
                      << " parsed=" << stats.parsed_triples.load()
                      << " dup=" << stats.duplicates.load()
                      << " elapsed=" << std::fixed << std::setprecision(2) << e << "s\n";
        }
    }

    void write_summary(const Stats& stats, size_t file_count) {
        if (args_.no_summary || args_.summary.empty()) return;
        std::ofstream s(args_.summary, std::ios::binary | std::ios::trunc);
        if (!s) return;
        double elapsed = elapsed_seconds();
        s << "{\n"
          << "  \"version\": \"" << APP_VERSION << "\",\n"
          << "  \"generated_at\": \"" << now_iso() << "\",\n"
          << "  \"mode\": \"abc-native\",\n"
          << "  \"output\": \"" << json_escape(args_.output) << "\",\n"
          << "  \"format\": \"" << args_.format << "\",\n"
          << "  \"field\": \"" << args_.field << "\",\n"
          << "  \"parse_mode\": \"" << args_.parse_mode << "\",\n"
          << "  \"threads\": " << args_.threads << ",\n"
          << "  \"files_matched_filters\": " << file_count << ",\n"
          << "  \"files_scanned\": " << stats.files_scanned.load() << ",\n"
          << "  \"bytes_scanned\": " << stats.bytes_scanned.load() << ",\n"
          << "  \"candidate_lines\": " << stats.candidate_lines.load() << ",\n"
          << "  \"parsed_triples\": " << stats.parsed_triples.load() << ",\n"
          << "  \"field_hits_before_dedupe\": " << stats.field_hits.load() << ",\n"
          << "  \"written_results\": " << stats.written.load() << ",\n"
          << "  \"duplicates_removed\": " << stats.duplicates.load() << ",\n"
          << "  \"elapsed_seconds\": " << std::fixed << std::setprecision(3) << elapsed << ",\n"
          << "  \"written_per_second\": " << (elapsed > 0 ? stats.written.load() / elapsed : 0) << "\n"
          << "}\n";
    }

    Args args_;
    Matcher matcher_;
    Writer* writer_ = nullptr;
    std::mutex out_mutex_;
    std::unordered_set<std::string> seen_;
    std::atomic<bool> stop_{false};
    std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
};

[[maybe_unused]] static void print_stats(const Args& args, const Stats& stats, double elapsed) {
    if (args.quiet) return;
    std::cout << "\n完成 / Done\n";
    std::cout << "files_scanned=" << stats.files_scanned.load()
              << " bytes=" << stats.bytes_scanned.load()
              << " candidate=" << stats.candidate_lines.load()
              << " parsed=" << stats.parsed_triples.load()
              << " matched=" << stats.field_hits.load()
              << " written=" << stats.written.load()
              << " dup=" << stats.duplicates.load()
              << " elapsed=" << std::fixed << std::setprecision(3) << elapsed << "s\n";
    std::cout << "output=" << args.output << "\n";
}

static void print_help() {
    std::cout << R"HELP(rgs-native v5.0.1-console-fix

用法 / Usage:
  rgs                 # 先选择 CLI 交互式或浏览器 GUI
  rgs --menu          # 显示启动菜单
  rgs --cli           # 直接进入 CLI 交互式
  rgs --gui           # 打开本地浏览器 GUI
  rgs scan -p DATA -k KEY --field B -o result.csv --glob "*.txt"

极速固定字符串检索 / Fast fixed-string examples:
  rgs scan -p ./data -k alice --field B -o result.csv --format csv --glob "*.txt"
  rgs scan -p ./data -k example.com --field A -o a.csv --columns abc
  rgs scan -p ./data --keyword-file keys.txt --field ANY -o out.csv --threads 8

参数 / Options:
  -p, --path PATH             文件或目录，可重复
  -k, --keyword KEY           关键词，可重复
      --keyword-file FILE     一行一个关键词
  -o, --output FILE           输出文件，默认 rg_abc_results.csv
      --field ANY|A|B|C       检索字段，默认 B
      --format csv|txt|jsonl  输出格式，默认 csv
      --columns abc|full      abc 最快；full 输出 file,line,source_line,matches
      --parse urlpath|url|simple  urlpath 默认，simple 最快但 A 不能含 ':'
      --regex                 使用正则；固定字符串最快
      --ignore-case           ASCII 忽略大小写
      --no-dedupe             不按 A/B/C 去重
      --keep-matches          full 列时填充 matches，速度略慢
      --glob PATTERN          包含 glob，如 "*.txt"，可重复
      --exclude PATTERN       排除 glob/目录片段，可重复
      --max-filesize SIZE     跳过大文件，如 200M, 1G
      --limit N               最多写出 N 条唯一结果
      --threads N             线程数，默认 CPU 核数
      --summary FILE          写 summary JSON
      --quiet                 静默输出
      --self-test             运行内置测试

说明:
  本工具只处理本机授权文件。核心路径是：内存映射文件 -> 按行候选过滤 -> A/B/C 解析 -> 字段匹配 -> 内存 set 去重 -> 流式写出。
)HELP";
}

static bool arg_has_value(int i, int argc) { return i + 1 < argc; }

static bool parse_scan_args(int argc, char** argv, int start, Args& args, std::string* err) {
    args.scan = true;
    for (int i = start; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> std::string {
            if (!arg_has_value(i, argc)) { if (err) *err = std::string("Missing value for ") + name; return {}; }
            return argv[++i];
        };
        if (a == "-p" || a == "--path") args.paths.push_back(need(a.c_str()));
        else if (a == "-k" || a == "--keyword" || a == "--keywords") args.keywords.push_back(need(a.c_str()));
        else if (a == "--keyword-file") args.keyword_files.push_back(need(a.c_str()));
        else if (a == "-o" || a == "--output") args.output = need(a.c_str());
        else if (a == "--field") args.field = need(a.c_str());
        else if (a == "--format") args.format = need(a.c_str());
        else if (a == "--columns" || a == "--abc-columns") args.columns = need(a.c_str());
        else if (a == "--parse" || a == "--abc-parse") args.parse_mode = need(a.c_str());
        else if (a == "--regex") args.regex = true;
        else if (a == "--ignore-case" || a == "-i") args.ignore_case = true;
        else if (a == "--case-sensitive") args.ignore_case = false;
        else if (a == "--dedupe") args.dedupe = true;
        else if (a == "--no-dedupe" || a == "--dedupe-none") args.dedupe = false;
        else if (a == "--keep-matches" || a == "--abc-keep-matches") args.keep_matches = true;
        else if (a == "--quiet") args.quiet = true;
        else if (a == "--debug") args.debug = true;
        else if (a == "--glob") args.include_globs.push_back(need(a.c_str()));
        else if (a == "--exclude") args.exclude_globs.push_back(need(a.c_str()));
        else if (a == "--max-filesize") args.max_filesize = parse_size(need(a.c_str()));
        else if (a == "--limit") args.limit = static_cast<size_t>(std::stoull(need(a.c_str())));
        else if (a == "--progress-every") args.progress_every = static_cast<size_t>(std::stoull(need(a.c_str())));
        else if (a == "--threads") args.threads = static_cast<unsigned>(std::stoul(need(a.c_str())));
        else if (a == "--summary") { args.summary = need(a.c_str()); args.no_summary = false; }
        else if (a == "--no-summary") { args.summary.clear(); args.no_summary = true; }
        else if (a == "--help" || a == "-h") { args.help = true; return true; }
        else { if (err) *err = "Unknown option: " + a; return false; }
    }
    for (const auto& f : args.keyword_files) {
        auto ks = load_keywords_from_file(f);
        args.keywords.insert(args.keywords.end(), ks.begin(), ks.end());
    }
    return true;
}

static Args parse_args(int argc, char** argv, std::string* err) {
    Args args;
    if (argc <= 1) return args;
    std::string first = argv[1];
    if (first == "--help" || first == "-h" || first == "help") { args.help = true; return args; }
    if (first == "--self-test") { args.self_test = true; return args; }
    if (first == "--menu" || first == "menu") { return args; }
    if (first == "--cli" || first == "interactive" || first == "cli") { args.interactive = true; return args; }
    if (first == "--gui" || first == "gui") { args.gui = true; return args; }
    if (first == "scan") {
        parse_scan_args(argc, argv, 2, args, err);
        return args;
    }
    // Compatibility: allow rgs -p ... -k ... without the scan subcommand.
    parse_scan_args(argc, argv, 1, args, err);
    return args;
}

static std::string prompt_line(const std::string& label, const std::string& def = "") {
    std::cout << label;
    if (!def.empty()) std::cout << " [" << def << "]";
    std::cout << ": " << std::flush;
    std::string s;
    if (!std::getline(std::cin, s)) return def;
    s = trim_copy(s);
    if (s.empty()) return def;
    return s;
}

static bool prompt_bool(const std::string& label, bool def) {
    std::string d = def ? "Y/n" : "y/N";
    std::string s = lower_ascii(prompt_line(label + " (" + d + ")"));
    if (s.empty()) return def;
    return s == "y" || s == "yes" || s == "1" || s == "true" || s == "是";
}

static std::vector<std::string> prompt_multiline_keywords() {
    std::cout << "请输入关键词，一行一个；输入空行结束。\n";
    std::vector<std::string> ks;
    while (true) {
        std::cout << "keyword> " << std::flush;
        std::string s;
        if (!std::getline(std::cin, s)) break;
        s = trim_copy(s);
        if (s.empty()) break;
        ks.push_back(s);
    }
    return ks;
}

static int run_scan(Args args) {
    const bool quiet = args.quiet;
    const std::string output = args.output;
    Stats stats;
    std::string err;
    Scanner scanner(std::move(args));
    bool ok = scanner.run(stats, &err);
    double elapsed = scanner.elapsed_seconds();
    if (!ok) {
        std::cerr << "错误 / Error: " << err << "\n";
        return 1;
    }
    if (!quiet) {
        std::cout << "完成: written=" << stats.written.load()
                  << " matched=" << stats.field_hits.load()
                  << " dup=" << stats.duplicates.load()
                  << " elapsed=" << std::fixed << std::setprecision(3) << elapsed << "s\n"
                  << "output=" << output << "\n";
    }
    return 0;
}

static int run_interactive_cli() {
    std::cout << "\n=== rgs-native CLI 交互式极速检索 ===\n" << std::flush;
    Args args;
    std::string path_line = prompt_line("检索路径，多个路径用 ; 分隔");
    args.paths = split_list(path_line, ';');
    std::string kw_mode = lower_ascii(prompt_line("关键词输入方式：1=单个/逗号分隔，2=多行", "1"));
    if (kw_mode == "2") args.keywords = prompt_multiline_keywords();
    else {
        std::string kws = prompt_line("关键词，多个关键词用逗号分隔");
        args.keywords = split_list(kws, ',');
    }
    args.field = prompt_line("检索字段 ANY/A/B/C", "B");
    args.output = prompt_line("输出文件", "rg_abc_results.csv");
    args.format = prompt_line("输出格式 csv/txt/jsonl", "csv");
    args.columns = prompt_line("输出列 abc/full，abc 最快", "abc");
    args.parse_mode = prompt_line("解析模式 urlpath/url/simple", "urlpath");
    std::string glob = prompt_line("include glob，空=全部，推荐 *.txt", "*.txt");
    if (!glob.empty()) args.include_globs.push_back(glob);
    args.ignore_case = prompt_bool("忽略大小写会略慢，是否启用", false);
    args.regex = prompt_bool("是否使用正则，固定字符串最快", false);
    args.dedupe = prompt_bool("是否按 A/B/C 去重", true);
    std::string threads = prompt_line("线程数，0=CPU 核数", "0");
    try { args.threads = static_cast<unsigned>(std::stoul(threads)); } catch (...) { args.threads = 0; }
    std::string limit = prompt_line("最多写出条数，0=不限", "0");
    try { args.limit = static_cast<size_t>(std::stoull(limit)); } catch (...) { args.limit = 0; }
    args.no_summary = true;
    return run_scan(args);
}

static std::string url_decode(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '+') out.push_back(' ');
        else if (c == '%' && i + 2 < in.size()) {
            auto hex = [](char x) -> int {
                if (x >= '0' && x <= '9') return x - '0';
                if (x >= 'a' && x <= 'f') return x - 'a' + 10;
                if (x >= 'A' && x <= 'F') return x - 'A' + 10;
                return -1;
            };
            int a = hex(in[i + 1]), b = hex(in[i + 2]);
            if (a >= 0 && b >= 0) { out.push_back(static_cast<char>((a << 4) | b)); i += 2; }
            else out.push_back(c);
        } else out.push_back(c);
    }
    return out;
}

static std::unordered_map<std::string, std::string> parse_form(std::string_view body) {
    std::unordered_map<std::string, std::string> m;
    size_t pos = 0;
    while (pos <= body.size()) {
        size_t amp = body.find('&', pos);
        std::string_view part = body.substr(pos, amp == std::string_view::npos ? body.size() - pos : amp - pos);
        size_t eq = part.find('=');
        if (eq != std::string_view::npos) {
            m[url_decode(part.substr(0, eq))] = url_decode(part.substr(eq + 1));
        }
        if (amp == std::string_view::npos) break;
        pos = amp + 1;
    }
    return m;
}

static std::string html_escape(std::string_view v) {
    std::string out;
    for (char ch : v) {
        switch (ch) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out.push_back(ch);
        }
    }
    return out;
}

static std::string gui_home_html() {
    return R"HTML(<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>rgs-native GUI</title><style>
body{font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;margin:28px;max-width:980px}label{display:block;margin:12px 0 4px}input,select,textarea{width:100%;padding:8px;font-size:14px;box-sizing:border-box}button{margin-top:16px;padding:10px 18px;font-size:15px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.hint{color:#666}.warn{background:#fff8db;padding:10px;border:1px solid #e6d27a}</style></head><body>
<h1>rgs-native A/B/C 极速检索</h1><p class="warn">仅用于本机授权文件的数据审计。大数据量最快建议使用 CLI。</p>
<form method="post" action="/run">
<label>检索路径；多个路径用 ; 分隔</label><input name="paths" placeholder="D:\\logs;E:\\data 或 /data/logs">
<label>关键词；多个关键词用逗号分隔</label><input name="keywords" placeholder="alice,example.com">
<div class="row"><div><label>字段</label><select name="field"><option>B</option><option>A</option><option>C</option><option>ANY</option></select></div><div><label>输出文件</label><input name="output" value="rg_abc_results.csv"></div></div>
<div class="row"><div><label>输出格式</label><select name="format"><option>csv</option><option>txt</option><option>jsonl</option></select></div><div><label>输出列</label><select name="columns"><option>abc</option><option>full</option></select></div></div>
<div class="row"><div><label>解析模式</label><select name="parse"><option>urlpath</option><option>url</option><option>simple</option></select></div><div><label>include glob</label><input name="glob" value="*.txt"></div></div>
<div class="row"><div><label>线程数 0=CPU</label><input name="threads" value="0"></div><div><label>最多写出 0=不限</label><input name="limit" value="0"></div></div>
<label><input type="checkbox" name="ignore_case" style="width:auto"> 忽略大小写</label>
<label><input type="checkbox" name="regex" style="width:auto"> 正则模式</label>
<label><input type="checkbox" name="no_dedupe" style="width:auto"> 不去重</label>
<button type="submit">开始检索</button>
</form><p class="hint">浏览器 GUI 调用同一个 C++ 本地引擎：内存映射、并行扫描、边解析边检索。</p></body></html>)HTML";
}

#ifdef _WIN32
using socket_t = SOCKET;
static void close_socket(socket_t s) { closesocket(s); }
#else
using socket_t = int;
static void close_socket(socket_t s) { close(s); }
#endif

static bool send_all(socket_t s, const std::string& data) {
    const char* p = data.data();
    size_t left = data.size();
    while (left > 0) {
#ifdef _WIN32
        int n = send(s, p, static_cast<int>(std::min<size_t>(left, 1 << 20)), 0);
#else
        ssize_t n = send(s, p, left, 0);
#endif
        if (n <= 0) return false;
        p += n;
        left -= static_cast<size_t>(n);
    }
    return true;
}

static void http_response(socket_t client, const std::string& body, const std::string& content_type = "text/html; charset=utf-8") {
    std::ostringstream os;
    os << "HTTP/1.1 200 OK\r\nContent-Type: " << content_type << "\r\nContent-Length: " << body.size()
       << "\r\nConnection: close\r\n\r\n" << body;
    send_all(client, os.str());
}

static void open_browser(int port) {
    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/";
#ifdef _WIN32
    std::string cmd = "start \"\" \"" + url + "\"";
#elif __APPLE__
    std::string cmd = "open \"" + url + "\"";
#else
    std::string cmd = "xdg-open \"" + url + "\" >/dev/null 2>&1 &";
#endif
    int browser_rc = std::system(cmd.c_str());
    (void)browser_rc;
}

static Args args_from_form(const std::unordered_map<std::string, std::string>& f) {
    Args a;
    auto get = [&](const std::string& k, const std::string& d = "") -> std::string {
        auto it = f.find(k);
        if (it == f.end() || trim_copy(it->second).empty()) return d;
        return trim_copy(it->second);
    };
    a.paths = split_list(get("paths"), ';');
    a.keywords = split_list(get("keywords"), ',');
    a.field = get("field", "B");
    a.output = get("output", "rg_abc_results.csv");
    a.format = get("format", "csv");
    a.columns = get("columns", "abc");
    a.parse_mode = get("parse", "urlpath");
    std::string glob = get("glob", "*.txt");
    if (!glob.empty()) a.include_globs.push_back(glob);
    a.ignore_case = f.count("ignore_case") > 0;
    a.regex = f.count("regex") > 0;
    a.dedupe = f.count("no_dedupe") == 0;
    try { a.threads = static_cast<unsigned>(std::stoul(get("threads", "0"))); } catch (...) { a.threads = 0; }
    try { a.limit = static_cast<size_t>(std::stoull(get("limit", "0"))); } catch (...) { a.limit = 0; }
    a.quiet = true;
    a.no_summary = true;
    return a;
}

static void handle_client(socket_t client) {
    std::string req;
    char buf[8192];
    while (req.find("\r\n\r\n") == std::string::npos && req.size() < 1024 * 1024) {
#ifdef _WIN32
        int n = recv(client, buf, sizeof(buf), 0);
#else
        ssize_t n = recv(client, buf, sizeof(buf), 0);
#endif
        if (n <= 0) { close_socket(client); return; }
        req.append(buf, buf + n);
    }
    size_t header_end = req.find("\r\n\r\n");
    if (header_end == std::string::npos) { close_socket(client); return; }
    std::string header = req.substr(0, header_end);
    std::string first_line = header.substr(0, header.find("\r\n"));
    size_t content_length = 0;
    std::istringstream hs(header);
    std::string line;
    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string low = lower_ascii(line);
        if (starts_with(low, "content-length:")) {
            content_length = static_cast<size_t>(std::stoull(trim_copy(line.substr(15))));
        }
    }
    std::string body = req.substr(header_end + 4);
    while (body.size() < content_length) {
#ifdef _WIN32
        int n = recv(client, buf, sizeof(buf), 0);
#else
        ssize_t n = recv(client, buf, sizeof(buf), 0);
#endif
        if (n <= 0) break;
        body.append(buf, buf + n);
    }
    if (starts_with(first_line, "GET / ") || starts_with(first_line, "GET /HTTP")) {
        http_response(client, gui_home_html());
    } else if (starts_with(first_line, "POST /run ")) {
        auto form = parse_form(body);
        Args args = args_from_form(form);
        Stats stats;
        std::string err;
        Scanner scanner(args);
        auto ok = scanner.run(stats, &err);
        double elapsed = scanner.elapsed_seconds();
        std::ostringstream html;
        html << "<!doctype html><html><head><meta charset='utf-8'><title>rgs result</title>"
             << "<style>body{font-family:system-ui;margin:28px}pre{background:#f5f5f5;padding:12px}</style></head><body>";
        if (!ok) {
            html << "<h1>失败</h1><pre>" << html_escape(err) << "</pre><p><a href='/'>返回</a></p>";
        } else {
            html << "<h1>完成</h1><pre>"
                 << "output=" << html_escape(args.output) << "\n"
                 << "files_scanned=" << stats.files_scanned.load() << "\n"
                 << "candidate=" << stats.candidate_lines.load() << "\n"
                 << "parsed=" << stats.parsed_triples.load() << "\n"
                 << "matched=" << stats.field_hits.load() << "\n"
                 << "written=" << stats.written.load() << "\n"
                 << "duplicates=" << stats.duplicates.load() << "\n"
                 << "elapsed=" << std::fixed << std::setprecision(3) << elapsed << "s\n"
                 << "</pre><p><a href='/'>继续检索</a></p>";
        }
        html << "</body></html>";
        http_response(client, html.str());
    } else {
        http_response(client, "Not found", "text/plain; charset=utf-8");
    }
    close_socket(client);
}

static int run_gui_server() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    socket_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (server_fd == INVALID_SOCKET) { std::cerr << "socket failed\n"; return 1; }
#else
    if (server_fd < 0) { std::cerr << "socket failed\n"; return 1; }
#endif
    int opt = 1;
#ifdef _WIN32
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    int port = 17627;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    for (; port < 17700; ++port) {
        addr.sin_port = htons(static_cast<uint16_t>(port));
        if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) break;
    }
    if (port >= 17700) { std::cerr << "Cannot bind localhost port\n"; return 1; }
    if (listen(server_fd, 16) != 0) { std::cerr << "listen failed\n"; return 1; }
    std::cout << "GUI running at http://127.0.0.1:" << port << "/\n";
    std::cout << "Press Ctrl+C to stop.\n" << std::flush;
    open_browser(port);
    while (true) {
        sockaddr_in caddr{};
#ifdef _WIN32
        int clen = sizeof(caddr);
        socket_t client = accept(server_fd, reinterpret_cast<sockaddr*>(&caddr), &clen);
        if (client == INVALID_SOCKET) continue;
#else
        socklen_t clen = sizeof(caddr);
        socket_t client = accept(server_fd, reinterpret_cast<sockaddr*>(&caddr), &clen);
        if (client < 0) continue;
#endif
        std::thread(handle_client, client).detach();
    }
}

static int run_start_menu() {
    while (true) {
        std::cout << "\n=== rgs-native v" << APP_VERSION << " ===\n"
                  << "1) CLI 交互式极速检索\n"
                  << "2) GUI 浏览器界面\n"
                  << "q) 退出\n"
                  << "请选择 [1]: " << std::flush;
        std::string s;
        if (!std::getline(std::cin, s)) return 0;
        s = trim_copy(lower_ascii(s));
        if (s.empty() || s == "1" || s == "cli" || s == "c") return run_interactive_cli();
        if (s == "2" || s == "gui" || s == "g") return run_gui_server();
        if (s == "q" || s == "quit" || s == "exit") return 0;
        std::cout << "无效输入，请输入 1、2 或 q。\n" << std::flush;
    }
}

static int self_test() {
    struct Case { std::string line; std::string a,b,c; std::string mode; };
    std::vector<Case> cases = {
        {"https://example.test/path:user1:pass1", "https://example.test/path", "user1", "pass1", "urlpath"},
        {"https://example.test/path/:user2:pa:ss:2", "https://example.test/path/", "user2", "pa:ss:2", "urlpath"},
        {"https://example.test:8443/path:user3:pass3", "https://example.test:8443/path", "user3", "pass3", "urlpath"},
        {"https://www.kenhub.com/:Cloud Link - TG-ABC:def", "https://www.kenhub.com/", "Cloud Link - TG-ABC", "def", "urlpath"},
        {"plainA:plainB:plainC:tail", "plainA", "plainB", "plainC:tail", "simple"},
    };
    for (const auto& c : cases) {
        auto got = parse_triple(c.line, c.mode);
        if (!got || got->a != c.a || got->b != c.b || got->c != c.c) {
            std::cerr << "parse failed: " << c.line << "\n";
            return 1;
        }
    }
    fs::path tmp = fs::temp_directory_path() / ("rgs_native_test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(tmp);
    fs::path sample = tmp / "sample.txt";
    {
        std::ofstream f(sample, std::ios::binary);
        f << "https://alpha.test/login:Alice:one\n";
        f << "https://alpha.test/login:Alice:one\n";
        f << "https://alpha.test/login:Bob:two\n";
        f << "https://beta.test:8443/path:Carol:three:tail\n";
        f << "not-a-triple\n";
    }
    Args a;
    a.paths.push_back(sample.string());
    a.keywords.push_back("Alice");
    a.field = "B";
    a.output = (tmp / "out.csv").string();
    a.format = "csv";
    a.columns = "abc";
    a.parse_mode = "urlpath";
    a.quiet = true;
    a.no_summary = true;
    Stats st;
    std::string err;
    Scanner sc(a);
    if (!sc.run(st, &err) || st.written.load() != 1 || st.duplicates.load() != 1) {
        std::cerr << "scan failed: " << err << " written=" << st.written.load() << " dup=" << st.duplicates.load() << "\n";
        return 1;
    }
    std::ifstream in(a.output, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(in)), {});
    if (content.find("https://alpha.test/login,Alice,one") == std::string::npos) {
        std::cerr << "output content failed\n";
        return 1;
    }
    std::error_code ec;
    fs::remove_all(tmp, ec);
    std::cout << "self-test ok\n";
    return 0;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    std::ios::sync_with_stdio(false);
    std::cin.tie(&std::cout);
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    std::string err;
    Args args = parse_args(argc, argv, &err);
    if (!err.empty()) { std::cerr << err << "\n"; return 2; }
    if (args.help) { print_help(); return 0; }
    if (args.self_test) return self_test();
    if (args.interactive) return run_interactive_cli();
    if (args.gui) return run_gui_server();
    if (args.scan) return run_scan(args);
    return run_start_menu();
}

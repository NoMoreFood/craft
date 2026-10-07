#pragma once

// CRAFT: Certificate Request Agent For Tickets.
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/random.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <concepts>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <limits>
#include <map>
#include <ranges>
#include <regex>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace craft
{
inline constexpr char CONFIG_DIR[] = "/etc/craft";
inline constexpr char LAUNCHER[] = "/usr/local/bin/craft";
inline constexpr char CACHE_LOCK[] = ".krb5cc_craft.lock";
inline constexpr char MAINTAIN_LOCK[] = ".krb5cc_craft.maintain.lock";
inline constexpr char WORKER[] = "/usr/local/libexec/craft-worker";
inline constexpr char SERVICE_USER[] = "craft";
inline constexpr char CACHE_NAME[] = ".krb5cc_craft";
inline constexpr size_t MAX_BLOB = 1024 * 1024;
using Bytes = std::vector<unsigned char>;
using ByteView = std::span<const unsigned char>;

// Report failures without allocating diagnostic strings on successful checks.
[[noreturn]] inline void fail(std::string_view message)
{
    // Throw runtime error with diagnostic failure message.
    throw std::runtime_error(std::string(message));
}

inline void need(bool ok, std::string_view message)
{
    // Validate boolean condition and fail if false.
    if (!ok) fail(message);
}

inline void sysneed(bool ok, std::string_view message)
{
    // Validate system call result and format errno description on error.
    if (!ok)
    {
        const int error = errno;
        fail(std::format("{}: {}", message, std::strerror(error)));
    }
}

// Run a nonthrowing cleanup exactly once unless explicitly dismissed.
template <std::invocable F>
    requires std::is_nothrow_invocable_v<F &> && std::is_nothrow_move_constructible_v<F>
class ScopeExit
{
    [[no_unique_address]] F cleanup_;
    bool active_ = true;

public:
    explicit ScopeExit(F cleanup) noexcept : cleanup_(std::move(cleanup))
    {
        // Initialize deferred action wrapper with move semantics.
    }

    ~ScopeExit() noexcept
    {
        // Execute the deferred cleanup callback if still active.
        if (active_) cleanup_();
    }

    ScopeExit(const ScopeExit &) = delete;

    ScopeExit &operator=(const ScopeExit &) = delete;

    void release() noexcept
    {
        // Dismiss scheduled cleanup execution.
        active_ = false;
    }
};

// Keep descriptor ownership explicit across moves and privilege changes.
class Fd
{
    int fd_ = -1;

public:
    explicit Fd(int fd = -1) noexcept : fd_(fd)
    {
        // Wrap descriptor handle with RAII ownership.
    }

    ~Fd()
    {
        // Close open file descriptor upon destruction.
        if (fd_ >= 0) ::close(fd_);
    }

    Fd(const Fd &) = delete;

    Fd &operator=(const Fd &) = delete;

    Fd(Fd &&other) noexcept : fd_(other.release())
    {
        // Transfer descriptor ownership from source instance.
    }

    Fd &operator=(Fd &&other) noexcept
    {
        // Close current descriptor and adopt transferred descriptor.
        if (this != &other)
        {
            if (fd_ >= 0) ::close(fd_);
            fd_ = other.release();
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept
    {
        // Expose internal descriptor without releasing ownership.
        return fd_;
    }

    [[nodiscard]] int release() noexcept
    {
        // Relinquish descriptor ownership and return raw handle.
        return std::exchange(fd_, -1);
    }
};

// Use sized views for byte transfers and non-elidable erasure for secret buffers.
inline ByteView byte_view(std::string_view text) noexcept
{
    // Reinterpret string buffer as a read-only byte view.
    return {reinterpret_cast<const unsigned char *>(text.data()), text.size()};
}

inline void wipe(std::span<unsigned char> bytes) noexcept
{
    // Erase sensitive bytes from memory without dead-store elimination.
    if (!bytes.empty()) ::explicit_bzero(bytes.data(), bytes.size());
}

inline void write_all(int fd, ByteView bytes)
{
    // Write entire byte buffer across interrupt retries until completed.
    while (!bytes.empty())
    {
        const auto count = ::write(fd, bytes.data(), bytes.size());
        if (count < 0 && errno == EINTR) continue;
        sysneed(count > 0, "write");
        bytes = bytes.subspan(static_cast<size_t>(count));
    }
}

inline Bytes read_all(int fd, size_t maximum = MAX_BLOB)
{
    Bytes bytes;
    std::array<unsigned char, 8192> buffer{};
    ScopeExit erase_bytes([&]() noexcept { wipe(bytes); });
    ScopeExit erase_buffer([&]() noexcept { wipe(buffer); });

    // Read descriptor data into temporary buffer chunk by chunk.
    for (;;)
    {
        const auto count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        sysneed(count >= 0, "read");
        if (!count)
        {
            erase_bytes.release();
            return bytes;
        }

        // Enforce buffer size limit and accumulate read bytes.
        need(static_cast<size_t>(count) <= maximum - bytes.size(), "input exceeds size limit");
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
    }
}

// Parse names and unsigned values without locale rules or implicit coercions.
inline std::string trim(std::string_view text)
{
    // Strip leading and trailing whitespace characters.
    const auto first = text.find_first_not_of(" \t\r\n");
    return first == text.npos ? ""
                              : std::string(text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1));
}

inline bool simple_name(std::string_view name) noexcept
{
    // Validate name syntax against safe POSIX account identifier rules.
    return !name.empty() && name.size() <= 64 &&
           ((name.front() >= 'a' && name.front() <= 'z') || name.front() == '_') &&
           name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_.-") == name.npos;
}

inline uint32_t number(std::string_view text, uint32_t maximum = UINT32_MAX)
{
    // Parse decimal character sequence into bounded unsigned integer.
    need(!text.empty() && text.size() < 11, "invalid unsigned integer");
    uint32_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    need(error == std::errc{} && end == text.data() + text.size() && value <= maximum,
         "invalid or out-of-range unsigned integer");
    return value;
}

// Resolve trusted passwd/NSS identity rather than caller-controlled environment values.
struct Account
{
    uid_t uid;
    gid_t gid;
    std::string name, home;
};

inline Account lookup_uid(uid_t uid)
{
    // Query NSS passwd database using reentrant getpwuid_r lookup.
    std::array<char, 16384> buffer{};
    passwd entry{}, *result = nullptr;
    const int rc = getpwuid_r(uid, &entry, buffer.data(), buffer.size(), &result);
    need(rc == 0 && result, "real UID does not resolve to a local/NSS account");
    return {.uid = result->pw_uid, .gid = result->pw_gid, .name = result->pw_name, .home = result->pw_dir};
}

inline Account service_account()
{
    // Query NSS passwd database for dedicated service account.
    std::array<char, 16384> buffer{};
    passwd entry{}, *result = nullptr;
    const int rc = getpwnam_r(SERVICE_USER, &entry, buffer.data(), buffer.size(), &result);
    need(rc == 0 && result && result->pw_uid != 0 && result->pw_gid != 0,
         "dedicated craft account is missing or unsafe");
    return {.uid = result->pw_uid, .gid = result->pw_gid, .name = result->pw_name, .home = result->pw_dir};
}

// Walk root-controlled paths component by component without following symlinks.
inline Fd root_open(const std::string &path, bool secret = false, bool executable = false)
{
    // Open root filesystem directory as secure base descriptor.
    need(path.starts_with('/'), "trusted path must be absolute");
    Fd dir(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    sysneed(dir.get() >= 0, "open /");
    size_t start = 1;

    // Walk directory components sequentially with O_NOFOLLOW.
    for (;;)
    {
        const auto slash = path.find('/', start);
        const bool last = slash == path.npos;
        const auto part = path.substr(start, last ? path.npos : slash - start);
        need(!part.empty() && part != "." && part != "..", "invalid trusted path component");
        const int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (last ? O_NONBLOCK : O_DIRECTORY);
        Fd next(::openat(dir.get(), part.c_str(), flags));
        sysneed(next.get() >= 0, "open trusted path " + path);
        struct stat st{};
        sysneed(fstat(next.get(), &st) == 0, "fstat trusted path");
        need(st.st_uid == 0 && !(st.st_mode & 0022),
             "trusted path must be root-owned and not group/world-writable: " + path);

        // Verify file type, size bounds, and permissions on terminal component.
        if (last)
        {
            need(S_ISREG(st.st_mode), "trusted file is not regular");
            need(st.st_size >= 0 && static_cast<uint64_t>(st.st_size) <= 8 * MAX_BLOB,
                 "trusted file is too large");
            if (secret) need(!(st.st_mode & 0007), "secret must not be accessible to other users");
            if (executable)
                need((st.st_mode & 0111) && !(st.st_mode & (S_ISUID | S_ISGID)), "worker mode is unsafe");
            return next;
        }
        need(S_ISDIR(st.st_mode), "trusted parent is not a directory");
        dir = std::move(next);
        start = slash + 1;
    }
}

inline std::string root_text(const std::string &path, size_t maximum = 65536)
{
    // Read root-owned text configuration file and verify it contains no embedded NUL.
    const Fd file = root_open(path);
    const auto bytes = read_all(file.get(), maximum);
    need(std::ranges::find(bytes, 0) == bytes.end(), "NUL in configuration");
    return {bytes.begin(), bytes.end()};
}

// Identity mapping resolving runtime UID/name to Active Directory identity.
struct Mapping
{
    uid_t uid;
    std::string name, upn;
};

inline std::string domain_to_dn(std::string_view domain)
{
    // Build LDAP distinguished name from DNS domain components.
    std::string dn;
    for (auto part : domain | std::views::split('.'))
    {
        if (!dn.empty()) dn += ",";
        dn += "DC=";
        dn.append(part.begin(), part.end());
    }
    return dn;
}

// Disable dumps, close inherited descriptors, and permanently relinquish elevated IDs.
inline void no_core()
{
    // Disable core dumping, set non-dumpable flag, and enforce restrictive umask.
    const rlimit limit{0, 0};
    sysneed(setrlimit(RLIMIT_CORE, &limit) == 0, "disable core files");
    sysneed(prctl(PR_SET_DUMPABLE, 0) == 0, "disable dumpability");
    ::umask(0077);
}

inline void close_from(unsigned first)
{
    // Attempt bulk file descriptor closure via close_range system call.
#ifdef SYS_close_range
    if (syscall(SYS_close_range, first, ~0U, 0) == 0) return;
    need(errno == ENOSYS || errno == EINVAL, "close_range failed");
#endif

    // Fall back to iterating file descriptors up to open file limit.
    rlimit limit{};
    sysneed(getrlimit(RLIMIT_NOFILE, &limit) == 0, "getrlimit");
    const auto maximum = limit.rlim_max == RLIM_INFINITY ? 1048576 : limit.rlim_max;
    for (rlim_t fd = first; fd < maximum; ++fd)
        ::close(static_cast<int>(fd));
}

inline void drop(uid_t uid, gid_t gid, std::span<const gid_t> groups = {})
{
    // Relinquish elevated group and user credentials and set no_new_privs.
    sysneed(setgroups(groups.size(), groups.empty() ? nullptr : groups.data()) == 0, "setgroups");
    sysneed(setresgid(gid, gid, gid) == 0, "setresgid");
    sysneed(setresuid(uid, uid, uid) == 0, "setresuid");
    need(getuid() == uid && geteuid() == uid && getgid() == gid && getegid() == gid,
         "credential drop failed");
    sysneed(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
    no_core();
}

// Generate unpredictable names from the kernel random source.
inline std::string random_hex(size_t count = 16)
{
    need(count <= MAX_BLOB, "random input exceeds size limit");
    Bytes bytes(count);
    auto remaining = std::span(bytes);

    // Collect cryptographically strong random bytes from kernel source.
    while (!remaining.empty())
    {
        const auto n = getrandom(remaining.data(), remaining.size(), 0);
        if (n < 0 && errno == EINTR) continue;
        sysneed(n > 0, "getrandom");
        remaining = remaining.subspan(static_cast<size_t>(n));
    }
    constexpr std::string_view hex = "0123456789abcdef";
    std::string result;
    result.reserve(2 * count);

    // Format binary random bytes into hexadecimal text string.
    for (const auto byte : bytes)
    {
        result += hex[byte >> 4];
        result += hex[byte & 15];
    }
    return result;
}

// Open the caller-owned cache directory after privilege has been relinquished.
inline Fd caller_home(const Account &caller)
{
    // Verify caller home directory format and path characters.
    const static std::regex home_re(R"(^/(?:[^/\x00-\x1f\x7f]+/)*[^/\x00-\x1f\x7f]+$)");
    need(std::regex_match(caller.home, home_re), "invalid home directory");

    // Verify caller home directory ownership and restrictive file permissions.
    Fd home(open(caller.home.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    sysneed(home.get() >= 0, "open caller home after privilege drop");
    struct stat st{};
    sysneed(fstat(home.get(), &st) == 0, "stat home");
    need(st.st_uid == caller.uid && !(st.st_mode & 0022),
         "home must belong to caller and not be group/world-writable");

    return home;
}

struct UserIdentityFiles
{
    Fd certificate{};
    Fd key{};
};

// Open an optional PEM pair using only the caller's filesystem permissions.
inline UserIdentityFiles user_identity_files(const Account &caller)
{
    need(getuid() == caller.uid && geteuid() == caller.uid,
         "user certificate must be opened after dropping to the caller");
    Fd directory = caller_home(caller);
    bool safe_directory = true;

    // Resolve the fixed location without following user-controlled symlinks.
    for (const char *name : {".config", "craft"})
    {
        Fd next(openat(directory.get(), name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (next.get() < 0 && errno == ENOENT) return {};
        sysneed(next.get() >= 0, "open ~/.config/craft for user certificate");
        struct stat st{};
        sysneed(fstat(next.get(), &st) == 0, "stat user certificate directory");
        safe_directory = safe_directory && st.st_uid == caller.uid && !(st.st_mode & 0022);
        directory = std::move(next);
    }

    // Only an entirely absent pair selects enrollment; partial or unsafe inputs fail.
    std::array<Fd, 2> files;
    constexpr std::array names{"user.pem", "user.key"};
    for (size_t i = 0; i < files.size(); ++i)
    {
        files[i] = Fd(openat(directory.get(), names[i], O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
        if (files[i].get() < 0 && errno == ENOENT) continue;
        sysneed(files[i].get() >= 0, std::format("open ~/.config/craft/{}", names[i]));
        struct stat st{};
        sysneed(fstat(files[i].get(), &st) == 0, "stat user certificate/key");
        need(S_ISREG(st.st_mode) && st.st_uid == caller.uid && st.st_nlink == 1 &&
                 !(st.st_mode & (i == 0 ? 0022 : 0077)),
             "user certificate/key must be caller-owned regular files; user.key must be private (mode 0600)");
        need(st.st_size > 0 && static_cast<uint64_t>(st.st_size) <= MAX_BLOB,
             "user certificate/key must be nonempty and at most 1 MiB each");
    }
    if (files[0].get() < 0 && files[1].get() < 0) return {};
    need(safe_directory,
         "user certificate directories must belong to caller and not be group/world-writable");
    need(files[0].get() >= 0 && files[1].get() >= 0,
         "incomplete user certificate pair; provide both ~/.config/craft/user.pem and user.key");

    return {std::move(files[0]), std::move(files[1])};
}

// Serialize cache changes using a private, stable lock file.
inline Fd cache_lock(int home, const char *name)
{
    Fd lock(openat(home, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600));
    sysneed(lock.get() >= 0, "open cache lock");
    struct stat st{};
    sysneed(fstat(lock.get(), &st) == 0, "stat cache lock");
    need(S_ISREG(st.st_mode) && st.st_uid == getuid() && st.st_nlink == 1 && !(st.st_mode & 0077),
         "cache lock must be caller-owned, regular and private");
    while (flock(lock.get(), LOCK_EX) != 0)
        if (errno != EINTR) fail("lock credential cache");
    return lock;
}

// Publish a private cache atomically only after dropping to the caller.
inline void publish_cache(const Account &caller, ByteView cache)
{
    const Fd home = caller_home(caller);

    // Open temporary cache file with exclusive creation flags in caller home.
    const auto temporary = std::format("{}.tmp.{}", CACHE_NAME, random_hex());
    const Fd out(
        openat(home.get(), temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    sysneed(out.get() >= 0, "create cache");
    ScopeExit cleanup([&]() noexcept { unlinkat(home.get(), temporary.c_str(), 0); });

    // Write cache payload, synchronize to disk, and rename atomically into place.
    write_all(out.get(), cache);
    sysneed(fsync(out.get()) == 0, "sync cache");
    sysneed(renameat(home.get(), temporary.c_str(), home.get(), CACHE_NAME) == 0, "publish cache");
    cleanup.release();
    sysneed(fsync(home.get()) == 0, "sync home directory");
}

} // namespace craft

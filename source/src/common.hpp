#pragma once

// CRAFT: Certificate Request Agent For Tickets.
// Dependency-free process and file primitives shared by every binary. The setuid launcher compiles this
// header and nothing else: whatever it does not use belongs in unprivileged.hpp.
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <concepts>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <format>
#include <initializer_list>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

// glibc 2.28 (RHEL 8) predates these names; the numbers are common to every architecture RHEL supports.
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif

// Installation layout; CMakeLists.txt overrides these for packaged builds.
#ifndef CRAFT_CONFIG_DIR
#define CRAFT_CONFIG_DIR "/etc/craft"
#endif
#ifndef CRAFT_RUNTIME_DIR
#define CRAFT_RUNTIME_DIR "/run/craft"
#endif
#ifndef CRAFT_LAUNCHER
#define CRAFT_LAUNCHER "/usr/local/bin/craft"
#endif
#ifndef CRAFT_WORKER
#define CRAFT_WORKER "/usr/local/libexec/craft-worker"
#endif

namespace craft
{
inline constexpr char CONFIG_DIR[] = CRAFT_CONFIG_DIR;
inline constexpr char RUNTIME_DIR[] = CRAFT_RUNTIME_DIR;
inline constexpr char LAUNCHER[] = CRAFT_LAUNCHER;
inline constexpr char WORKER[] = CRAFT_WORKER;
inline constexpr char SERVICE_USER[] = "craft";
inline constexpr char CACHE_NAME[] = ".krb5cc_craft";
inline constexpr char CACHE_LOCK[] = ".krb5cc_craft.lock";
inline constexpr size_t MAX_BLOB = 1024 * 1024;
inline constexpr unsigned ACQUISITION_SECONDS = 400;

// The policy worker sends only these bounded mode identifiers to the elevated launcher.
enum class CertificateSource : unsigned char
{
    Enrollment,
    Home,
    KeyTrust,
    ConstrainedDelegation
};
inline constexpr std::array<std::string_view, 4> MODE_NAMES{
    "enrollment", "home", "key_trust", "constrained_delegation"};
using Bytes = std::vector<unsigned char>;
using ByteView = std::span<const unsigned char>;

// Every failure is an exception. Its summary is fit for the caller to read; detail that names system files,
// repeats what a server or a library said, or echoes configuration follows it in what() and is meant for the
// audit log alone. Messages that are costly to build belong behind an explicit `if (...) fail(...)`, because
// arguments to need() are evaluated even when the check passes.
class Failure : public std::runtime_error
{
    size_t summary_;

public:
    explicit Failure(std::string_view summary, std::string_view detail = {})
        : std::runtime_error(detail.empty() ? std::string(summary) : std::format("{}: {}", summary, detail)),
          summary_(summary.size())
    {
    }

    [[nodiscard]] std::string_view summary() const noexcept
    {
        return std::string_view(what()).substr(0, summary_);
    }
};

[[noreturn]] inline void fail(std::string_view summary, std::string_view detail = {})
{
    throw Failure(summary, detail);
}

// The text of a system error names no file, so it belongs to the summary.
[[noreturn]] inline void sysfail(std::string_view message)
{
    const int error = errno;
    fail(std::format("{}: {}", message, std::strerror(error)));
}

inline void need(bool ok, std::string_view message)
{
    if (!ok) fail(message);
}

inline void sysneed(bool ok, std::string_view message)
{
    if (!ok) sysfail(message);
}

// Repeat a system call that a signal interrupted.
template <std::invocable F> inline auto retry(F &&call)
{
    for (;;)
        if (const auto result = call(); result >= 0 || errno != EINTR) return result;
}

// Run a nonthrowing cleanup exactly once unless dismissed.
template <std::invocable F>
    requires std::is_nothrow_invocable_v<F &> && std::is_nothrow_move_constructible_v<F>
class ScopeExit
{
    [[no_unique_address]] F cleanup_;
    bool active_ = true;

public:
    explicit ScopeExit(F cleanup) noexcept : cleanup_(std::move(cleanup))
    {
    }

    ~ScopeExit() noexcept
    {
        if (active_) cleanup_();
    }

    ScopeExit(const ScopeExit &) = delete;

    ScopeExit &operator=(const ScopeExit &) = delete;

    void release() noexcept
    {
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
    }

    ~Fd()
    {
        if (fd_ >= 0) ::close(fd_);
    }

    Fd(const Fd &) = delete;

    Fd &operator=(const Fd &) = delete;

    Fd(Fd &&other) noexcept : fd_(other.release())
    {
    }

    Fd &operator=(Fd &&other) noexcept
    {
        if (this != &other)
        {
            if (fd_ >= 0) ::close(fd_);
            fd_ = other.release();
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept
    {
        return fd_;
    }

    [[nodiscard]] int release() noexcept
    {
        return std::exchange(fd_, -1);
    }
};

struct Pipe
{
    Fd reader, writer;
};

inline Pipe make_pipe(int flags = 0)
{
    std::array<int, 2> ends{};
    sysneed(pipe2(ends.data(), O_CLOEXEC | flags) == 0, "pipe");
    return {Fd(ends[0]), Fd(ends[1])};
}

// Sized views for byte transfers, and erasure the optimizer may not remove for secret buffers.
inline ByteView byte_view(std::string_view text) noexcept
{
    return {reinterpret_cast<const unsigned char *>(text.data()), text.size()};
}

inline void wipe(std::span<unsigned char> bytes) noexcept
{
    if (!bytes.empty()) ::explicit_bzero(bytes.data(), bytes.size());
}

inline void write_all(int fd, ByteView bytes)
{
    while (!bytes.empty())
    {
        const auto count = retry([&] { return ::write(fd, bytes.data(), bytes.size()); });
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
    for (;;)
    {
        const auto count = retry([&] { return ::read(fd, buffer.data(), buffer.size()); });
        sysneed(count >= 0, "read");
        if (!count)
        {
            erase_bytes.release();
            return bytes;
        }
        need(static_cast<size_t>(count) <= maximum - bytes.size(), "input exceeds size limit");
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
    }
}

// Bound a diagnostic and blank everything but printable ASCII: it may reach a terminal, syslog or a status
// file.
inline std::string sanitize_ascii(std::string_view text, size_t maximum = 500)
{
    std::string clean(text.substr(0, maximum));
    for (char &c : clean)
        if (const auto byte = static_cast<unsigned char>(c); byte < 32 || byte > 126) c = ' ';
    return clean;
}

// The name this program reports and logs under; the worker and the maintainer set their own at startup.
inline const char *program = "craft";

// Hand one record to the host logging service and fail unless that service took it: CRAFT stops rather than
// act unrecorded. What happens beyond the socket (storage, forwarding, alarms) is the service's own duty. The
// record is bounded printable ASCII, so nothing a peer or a library says can forge another one.
inline void audit(int priority, std::string_view message)
{
    const sockaddr_un service{.sun_family = AF_UNIX, .sun_path = "/dev/log"};
    const time_t now = time(nullptr);
    tm local{};
    std::array<char, 16> stamp{};
    if (localtime_r(&now, &local)) std::strftime(stamp.data(), stamp.size(), "%b %e %T", &local);
    const auto record = std::format("<{}>{} {}[{}]: {}",
                                    LOG_AUTHPRIV | priority,
                                    stamp.data(),
                                    program,
                                    getpid(),
                                    sanitize_ascii(message, 900));

    // Wait out a brief logger backlog for at most a second: a stalled logger must not hold up directory
    // cleanup, whose guardian blocks ordinary signals.
    const Fd log(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    const timeval patience{1, 0};
    sysneed(log.get() >= 0 &&
                setsockopt(log.get(), SOL_SOCKET, SO_SNDTIMEO, &patience, sizeof(patience)) == 0 &&
                connect(log.get(), reinterpret_cast<const sockaddr *>(&service), sizeof(service)) == 0 &&
                retry([&] { return send(log.get(), record.data(), record.size(), MSG_NOSIGNAL); }) ==
                    static_cast<ssize_t>(record.size()),
            "submit an audit record to the host logging service");
}

// The same for a failure that is already being reported, when nothing is left to stop.
inline bool try_audit(int priority, std::string_view message) noexcept
{
    try
    {
        audit(priority, message);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

// What the caller is told about a failure: its summary and, when there is more, where an administrator can
// read the rest. Anything that is not a Failure is unexpected and is described no further.
inline std::string caller_notice(const std::exception &error)
{
    const auto *failure = dynamic_cast<const Failure *>(&error);
    const std::string_view summary = failure ? failure->summary() : "unexpected failure";
    if (failure && summary.size() == std::strlen(error.what())) return sanitize_ascii(summary);
    return sanitize_ascii(std::format("{}: see the system log under {}[{}]", summary, program, getpid()));
}

// Report a failure where a program gives up: all of it to the audit log, the notice to the caller.
inline void report(const std::exception &error, std::string_view context) noexcept
{
    try
    {
        (void)try_audit(LOG_WARNING, std::format("{} failed: {}", context, error.what()));
        dprintf(STDERR_FILENO, "%s: %s\n", program, caller_notice(error).c_str());
    }
    catch (...)
    {
    }
}

// Linux account names in strict ASCII syntax: nothing that could pass for a path, an option or a principal.
inline bool simple_name(std::string_view name) noexcept
{
    return !name.empty() && name.size() <= 64 &&
           ((name.front() >= 'a' && name.front() <= 'z') || name.front() == '_') &&
           name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_.-") == name.npos;
}

// Resolve identities through passwd/NSS, never through caller-controlled environment values.
struct Account
{
    uid_t uid;
    gid_t gid;
    std::string name, home;
};

inline Account lookup_uid(uid_t uid)
{
    std::array<char, 16384> buffer{};
    passwd entry{}, *found = nullptr;
    need(getpwuid_r(uid, &entry, buffer.data(), buffer.size(), &found) == 0 && found,
         "real UID does not resolve to a local/NSS account");
    return {found->pw_uid, found->pw_gid, found->pw_name, found->pw_dir};
}

inline Account service_account()
{
    std::array<char, 16384> buffer{};
    passwd entry{}, *found = nullptr;
    need(getpwnam_r(SERVICE_USER, &entry, buffer.data(), buffer.size(), &found) == 0 && found &&
             found->pw_uid != 0 && found->pw_gid != 0,
         "dedicated craft account is missing or unsafe");
    return {found->pw_uid, found->pw_gid, found->pw_name, found->pw_dir};
}

// What a root-controlled file is trusted for. Data and secrets are size-bounded because they are read or
// parsed; the two programs are only ever executed, and only the launcher may carry a set-ID bit.
enum class Trusted
{
    Data,
    Secret,
    Worker,
    Launcher
};

// Walk a root-controlled path component by component without following symlinks.
[[nodiscard]] inline Fd root_open(const std::string &path, Trusted kind = Trusted::Data)
{
    const auto require = [&](bool ok, std::string_view why)
    {
        if (!ok) fail(why, path);
    };
    require(path.starts_with('/'), "trusted path must be absolute");
    Fd dir(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    sysneed(dir.get() >= 0, "open /");
    for (size_t start = 1;;)
    {
        const auto slash = path.find('/', start);
        const bool last = slash == path.npos;
        const auto part = path.substr(start, last ? path.npos : slash - start);
        require(!part.empty() && part != "." && part != "..", "invalid trusted path component");
        const int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (last ? O_NONBLOCK : O_DIRECTORY);
        Fd next(::openat(dir.get(), part.c_str(), flags));
        if (next.get() < 0) fail(std::format("open trusted file: {}", std::strerror(errno)), path);
        struct stat st
        {
        };
        sysneed(fstat(next.get(), &st) == 0, "fstat trusted path");
        require(st.st_uid == 0 && !(st.st_mode & 0022),
                "trusted file and its directories must be root-owned and not group/world-writable");
        if (last)
        {
            require(S_ISREG(st.st_mode), "trusted file is not regular");
            if (kind == Trusted::Worker || kind == Trusted::Launcher)
                require((st.st_mode & 0111) &&
                            (kind == Trusted::Launcher || !(st.st_mode & (S_ISUID | S_ISGID))),
                        "trusted program mode is unsafe");
            else
                require(st.st_size >= 0 && static_cast<uint64_t>(st.st_size) <= 8 * MAX_BLOB,
                        "trusted file is too large");

            // Root owns a secret and others are denied, so only the service account's group can have opened
            // it.
            if (kind == Trusted::Secret)
                require(!(st.st_mode & 0007), "secret must not be accessible to other users");
            return next;
        }
        require(S_ISDIR(st.st_mode), "trusted parent is not a directory");
        dir = std::move(next);
        start = slash + 1;
    }
}

// Disable dumps, close inherited descriptors and permanently relinquish elevated IDs.
inline void no_core()
{
    const rlimit limit{0, 0};
    sysneed(setrlimit(RLIMIT_CORE, &limit) == 0, "disable core files");
    sysneed(prctl(PR_SET_DUMPABLE, 0) == 0, "disable dumpability");
    ::umask(0077);
}

// Open any closed standard descriptor, lowest first, so no later file can land on a standard stream.
inline void ensure_standard_streams()
{
    for (int fd = 0; fd < 3; ++fd)
        if (fcntl(fd, F_GETFD) < 0)
            sysneed(open("/dev/null", fd == 0 ? O_RDONLY : O_WRONLY) == fd, "open /dev/null");
}

// Close every open descriptor from `first` upward by enumerating /proc: exact, whereas a loop to the
// descriptor limit can run to a billion iterations.
inline void close_listed_from(int first)
{
    DIR *listing = opendir("/proc/self/fd");
    sysneed(listing != nullptr, "enumerate open descriptors");
    std::vector<int> open;
    while (const dirent *entry = readdir(listing))
    {
        int fd{};
        const auto end = entry->d_name + std::strlen(entry->d_name);
        if (std::from_chars(entry->d_name, end, fd).ptr == end && fd >= first && fd != dirfd(listing))
            open.push_back(fd);
    }
    closedir(listing);
    for (const int fd : open)
        ::close(fd);
}

// Close every descriptor from `first` upward. Kernels before 5.9 and strict seccomp profiles lack
// close_range.
inline void close_from(int first)
{
    if (syscall(SYS_close_range, static_cast<unsigned>(first), ~0U, 0U) != 0) close_listed_from(first);
}

// In a forked child, renumber the given descriptors to 3, 4, ... and close every other one above the standard
// streams; a negative entry leaves its slot closed. Owners of the old numbers are stale afterwards, so the
// child keeps no local Fd alive across this call and leaves through exec or _exit, as fork_child guarantees.
inline void keep_only(std::initializer_list<int> keep)
{
    const int above = 3 + static_cast<int>(keep.size());
    std::vector<int> lifted;
    for (const int fd : keep)
    {
        lifted.push_back(fd < 0 ? -1 : fcntl(fd, F_DUPFD_CLOEXEC, above));
        sysneed(fd < 0 || lifted.back() >= 0, "retain descriptor");
    }
    int target = 3;
    for (const int fd : lifted)
    {
        if (fd < 0) ::close(target);
        else sysneed(dup3(fd, target, O_CLOEXEC) == target, "install descriptor");
        ++target;
    }
    close_from(target);
}

inline void drop(uid_t uid, gid_t gid, std::span<const gid_t> groups = {})
{
    sysneed(setgroups(groups.size(), groups.empty() ? nullptr : groups.data()) == 0, "setgroups");
    sysneed(setresgid(gid, gid, gid) == 0, "setresgid");
    sysneed(setresuid(uid, uid, uid) == 0, "setresuid");
    need(getuid() == uid && geteuid() == uid && getgid() == gid && getegid() == gid,
         "credential drop failed");
    sysneed(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
    no_core();
}

inline pid_t waitpid_retry(pid_t pid, int *status = nullptr, int options = 0)
{
    return retry([&] { return ::waitpid(pid, status, options); });
}

// Fork a child that runs `body` and exits with its result. The child never returns into the parent's frames,
// so a failure cannot unwind into the parent's logic or run its cleanup a second time.
template <std::invocable F>
    requires std::convertible_to<std::invoke_result_t<F>, int>
inline pid_t fork_child(F &&body)
{
    const pid_t pid = fork();
    sysneed(pid >= 0, "fork");
    if (pid != 0) return pid;
    int status = 1;
    try
    {
        status = body();
    }
    catch (const std::exception &error)
    {
        report(error, "child process");
    }
    catch (...)
    {
    }
    _exit(status);
}

// Own a forked child until its status is collected; an abandoned child is killed where permitted, then
// reaped.
class Child
{
    pid_t pid_ = -1;
    bool group_ = false;

    void reap() noexcept
    {
        if (pid_ <= 0) return;
        if (group_) kill(-pid_, SIGKILL);

        // A child that changed identity cannot be signalled from here. It ends itself when this process
        // closes, or dies holding, the pipe that is the child's input: see exit_with_peer in
        // unprivileged.hpp.
        if (kill(pid_, SIGKILL) == 0 || errno != EPERM) waitpid_retry(pid_);
        pid_ = -1;
    }

public:
    explicit Child(pid_t pid, bool group = false) noexcept : pid_(pid), group_(group)
    {
    }

    ~Child()
    {
        reap();
    }

    Child(const Child &) = delete;

    Child &operator=(const Child &) = delete;

    [[nodiscard]] pid_t pid() const noexcept
    {
        return pid_;
    }

    // Collect the exit status once; signals never match an expected normal exit.
    [[nodiscard]] bool wait(int expected = 0)
    {
        int status{};
        const pid_t pid = std::exchange(pid_, -1);
        sysneed(waitpid_retry(pid, &status) == pid, "waitpid");
        return WIFEXITED(status) && WEXITSTATUS(status) == expected;
    }
};

// Unpredictable names and identifiers from the kernel random source.
inline Bytes random_bytes(size_t count)
{
    need(count <= MAX_BLOB, "random request exceeds size limit");
    Bytes bytes(count);
    for (auto remaining = std::span(bytes); !remaining.empty();)
    {
        const auto n = retry([&] { return getrandom(remaining.data(), remaining.size(), 0); });
        sysneed(n > 0, "getrandom");
        remaining = remaining.subspan(static_cast<size_t>(n));
    }
    return bytes;
}

inline std::string hex(ByteView bytes, bool upper = false)
{
    const std::string_view digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string text;
    text.reserve(2 * bytes.size());
    for (const auto byte : bytes)
    {
        text += digits[byte >> 4];
        text += digits[byte & 15];
    }
    return text;
}

inline std::string random_hex(size_t count = 16)
{
    return hex(random_bytes(count));
}

// True when the open directory belongs to `owner` and grants none of the `forbidden` permission bits.
inline bool owned_directory(int fd, uid_t owner, mode_t forbidden)
{
    struct stat st
    {
    };
    sysneed(fstat(fd, &st) == 0, "stat directory");
    return S_ISDIR(st.st_mode) && st.st_uid == owner && !(st.st_mode & forbidden);
}

// Open the caller-owned home directory after privilege has been relinquished.
inline Fd caller_home(const Account &caller)
{
    // Accept only an absolute path with nonempty components and no control characters.
    const std::string_view path = caller.home;
    need(path.size() > 1 && path.front() == '/' && path.back() != '/' && path.find("//") == path.npos &&
             std::ranges::none_of(path, [](unsigned char c) { return c < 32 || c == 127; }),
         "invalid home directory");
    Fd home(open(caller.home.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    sysneed(home.get() >= 0, "open caller home after privilege drop");
    need(owned_directory(home.get(), caller.uid, 0022),
         "home must belong to caller and not be group/world-writable");
    return home;
}

// Open a regular file that only this process's user can have altered, without following links. A missing file
// yields an empty Fd with errno set to ENOENT; pass O_CREAT to create it instead.
inline Fd open_private(int directory,
                       const char *name,
                       int flags,
                       std::string_view what,
                       mode_t forbidden = 0077,
                       off_t *size = nullptr)
{
    Fd file(openat(directory, name, flags | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600));
    if (file.get() < 0 && errno == ENOENT) return file;
    if (file.get() < 0) sysfail(std::format("open {}", what));
    struct stat st
    {
    };
    sysneed(fstat(file.get(), &st) == 0, "stat private file");
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 || (st.st_mode & forbidden) ||
        st.st_size < 0 || static_cast<uint64_t>(st.st_size) > MAX_BLOB)
        fail(std::format("{} must be a caller-owned regular file of at most 1 MiB without extra links or "
                         "access by other users",
                         what));
    if (size) *size = st.st_size;
    return file;
}

// Serialize cache changes through a private, stable lock file.
inline Fd cache_lock(int home, const char *name)
{
    Fd lock = open_private(home, name, O_RDWR | O_CREAT, "cache lock");
    sysneed(lock.get() >= 0, "open cache lock");
    sysneed(retry([&] { return flock(lock.get(), LOCK_EX); }) == 0, "lock credential cache");
    return lock;
}

// Replace a file in an already validated directory: write a private temporary, then rename it into place.
inline void replace_file(int directory, const std::string &name, ByteView bytes, bool durable)
{
    const auto temporary = std::format("{}.tmp.{}", name, random_hex());
    const Fd out(
        openat(directory, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    sysneed(out.get() >= 0, "create temporary file");
    ScopeExit cleanup([&]() noexcept { unlinkat(directory, temporary.c_str(), 0); });
    write_all(out.get(), bytes);
    if (durable) sysneed(fsync(out.get()) == 0, "sync temporary file");
    sysneed(renameat(directory, temporary.c_str(), directory, name.c_str()) == 0, "publish file");
    cleanup.release();

    // The rename is the commit point: a directory that cannot be synced must not report a failed publication.
    if (durable) (void)fsync(directory);
}

inline void publish_cache(int home, ByteView cache)
{
    replace_file(home, CACHE_NAME, cache, true);
}

} // namespace craft

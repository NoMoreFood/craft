#pragma once

// Helpers for the programs that run without privilege, the worker and the maintainer. The setuid launcher
// compiles common.hpp alone, so nothing here adds to the code that can run as root.
#include "common.hpp"
#include <poll.h>
#include <limits>

namespace craft
{
inline std::string text_of(ByteView bytes)
{
    return {bytes.begin(), bytes.end()};
}

// Parse unsigned values without locale rules or implicit coercions.
inline std::string trim(std::string_view text)
{
    const auto first = text.find_first_not_of(" \t\r\n");
    return first == text.npos ? ""
                              : std::string(text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1));
}

template <std::unsigned_integral T = uint32_t>
inline T number(std::string_view text, std::type_identity_t<T> maximum = std::numeric_limits<T>::max())
{
    T value{};
    const auto end = text.data() + text.size();
    const auto [parsed, error] = std::from_chars(text.data(), end, value);
    need(!text.empty() && text.size() <= static_cast<size_t>(std::numeric_limits<T>::digits10) + 1 &&
             error == std::errc{} && parsed == end && value <= maximum,
         "invalid or out-of-range unsigned integer");
    return value;
}

// A small state file is empty or holds one fixed-size record, replaced by a single write: an interrupted
// update leaves either the old or the new value.
inline constexpr size_t RECORD_SIZE = 64;

inline std::string read_record(int fd)
{
    std::array<char, RECORD_SIZE + 1> buffer{};
    const auto count = retry([&] { return pread(fd, buffer.data(), buffer.size(), 0); });
    sysneed(count >= 0, "read state record");
    need(count == 0 || static_cast<size_t>(count) == RECORD_SIZE, "state record is malformed");
    return trim({buffer.data(), static_cast<size_t>(count)});
}

inline void write_record(int fd, std::string_view text)
{
    const auto record = std::format("{:<{}}\n", text, RECORD_SIZE - 1);
    need(record.size() == RECORD_SIZE, "state record is too long");
    const auto count = retry([&] { return pwrite(fd, record.data(), record.size(), 0); });
    sysneed(count == static_cast<ssize_t>(record.size()), "write state record");
}

inline std::string root_text(const std::string &path, size_t maximum = 65536)
{
    const Fd file = root_open(path);
    const auto bytes = read_all(file.get(), maximum);
    need(std::ranges::find(bytes, 0) == bytes.end(), "NUL in configuration");
    return text_of(bytes);
}

// Validate a root-controlled file that a library will then open by its path. Checking first and opening
// later is sound here only because root alone can change any component of a trusted path.
inline void require_trusted(const std::string &path, Trusted kind = Trusted::Data)
{
    (void)root_open(path, kind);
}

// End this process, by the default action of SIGIO, once every writer of the pipe on `fd` has gone. A
// parent-death signal cannot do that for the service worker: the kernel delivers it with the dying parent's
// credentials, and by then the launcher has dropped to the caller. Anything but a pipe is left alone.
inline void exit_with_peer(int fd)
{
    struct stat st
    {
    };
    if (fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode)) return;
    sigset_t io;
    sigemptyset(&io);
    sigaddset(&io, SIGIO);
    sysneed(signal(SIGIO, SIG_DFL) != SIG_ERR && sigprocmask(SIG_UNBLOCK, &io, nullptr) == 0 &&
                fcntl(fd, F_SETOWN, getpid()) == 0 && fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_ASYNC) == 0,
            "watch the peer process");

    // A peer that went before the watch was armed raises no signal.
    pollfd peer{fd, 0, 0};
    need(poll(&peer, 1, 0) >= 0 && !(peer.revents & (POLLHUP | POLLERR | POLLNVAL)),
         "peer process disappeared");
}

// Serialize broker attempts and charge one cooldown per launcher-generated request identifier. Later modes
// share that admission; a new invocation cannot bypass it. Record admission before contacting a server.
inline Fd rate_limit(int directory, uid_t uid, uint32_t interval, time_t now, std::string_view request = {})
{
    Fd lock = open_private(directory, std::format("{}.lock", uid).c_str(), O_RDWR | O_CREAT, "issuance lock");
    sysneed(lock.get() >= 0, "open per-user issuance lock");
    sysneed(flock(lock.get(), LOCK_EX | LOCK_NB) == 0, "another issuance is already running for this user");

    // A timestamp from the future means the clock stepped back: restart the interval rather than block the
    // user.
    if (const auto last = read_record(lock.get()); !last.empty())
    {
        const auto space = last.find(' ');
        const auto then = number<uint64_t>(std::string_view(last).substr(0, space));
        const auto current = static_cast<uint64_t>(now);
        if (!request.empty() && space != last.npos && last.substr(space + 1) == request) return lock;
        need(then > current || current - then >= interval, "per-user enrollment rate limit reached");
    }
    write_record(lock.get(), request.empty() ? std::to_string(now) : std::format("{} {}", now, request));
    return lock;
}

} // namespace craft

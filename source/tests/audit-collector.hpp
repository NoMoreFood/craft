#pragma once

// A stand-in for the host logging service. A test binds a datagram socket of its own, and the linker's
// --wrap=connect sends every audit record there instead of to /dev/log; no production code knows of it.
#include "../src/common.hpp"

namespace craft::testing
{
inline std::string audit_socket; // empty: records go to the real /dev/log

inline sockaddr_un unix_address(std::string_view path)
{
    sockaddr_un address{.sun_family = AF_UNIX, .sun_path = {}};
    need(path.size() < sizeof(address.sun_path), "socket path is too long");
    std::ranges::copy(path, address.sun_path);
    return address;
}

class AuditCollector
{
    std::string path_;
    Fd socket_;

public:
    // Collect at `path`. With `redirect`, records sent by this process and its children arrive here; without
    // it the path is the real log socket and other programs find it by themselves.
    explicit AuditCollector(std::string path, bool redirect = true)
        : path_(std::move(path)), socket_(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0))
    {
        const auto address = unix_address(path_);
        unlink(path_.c_str());
        sysneed(socket_.get() >= 0 &&
                    bind(socket_.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0 &&
                    chmod(path_.c_str(), 0666) == 0,
                "bind the audit collector");
        if (redirect) audit_socket = path_;
    }

    ~AuditCollector()
    {
        audit_socket.clear();
        unlink(path_.c_str());
    }

    AuditCollector(const AuditCollector &) = delete;

    AuditCollector &operator=(const AuditCollector &) = delete;

    // The next record, or nothing when `wait` is false and none is queued.
    std::string next(bool wait)
    {
        std::array<char, 2048> buffer{};
        const auto count =
            retry([&] { return recv(socket_.get(), buffer.data(), buffer.size(), wait ? 0 : MSG_DONTWAIT); });
        if (count < 0 && !wait && (errno == EAGAIN || errno == EWOULDBLOCK)) return {};
        sysneed(count >= 0, "receive an audit record");
        return {buffer.data(), static_cast<size_t>(count)};
    }

    // Every record received since the last call, one per line.
    std::string records()
    {
        std::string all;
        for (auto record = next(false); !record.empty(); record = next(false))
            all += record + "\n";
        return all;
    }
};

} // namespace craft::testing

extern "C" int __real_connect(int, const sockaddr *, socklen_t);
extern "C" int __wrap_connect(int fd, const sockaddr *address, socklen_t length)
{
    using craft::testing::audit_socket;
    if (!audit_socket.empty() && address->sa_family == AF_UNIX &&
        std::string_view(reinterpret_cast<const sockaddr_un *>(address)->sun_path) == "/dev/log")
    {
        const auto redirected = craft::testing::unix_address(audit_socket);
        return __real_connect(fd, reinterpret_cast<const sockaddr *>(&redirected), sizeof(redirected));
    }
    return __real_connect(fd, address, length);
}

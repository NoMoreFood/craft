#pragma once

// Detached, unprivileged credential maintenance for an explicitly watched batch process.
#include "resources.hpp"
#include <poll.h>
#include <syslog.h>
#include <chrono>
#include <sstream>

// The test suite builds a second maintainer with this off to exercise kernels without pidfd_open (RHEL 8).
#ifndef CRAFT_USE_PIDFD
#define CRAFT_USE_PIDFD true
#endif

namespace craft::maintain
{
using Clock = std::chrono::steady_clock;
inline constexpr char MAINTAIN_LOCK[] = ".krb5cc_craft.maintain.lock";
inline constexpr char RETRY_STATE[] = ".krb5cc_craft.maintain.retry";
inline volatile sig_atomic_t stopping = 0;

struct Options
{
    pid_t watch = 0;
    uint32_t maximum = 0;
    bool status = false, help = false;
};

inline Options options(int argc, char **argv)
{
    Options result;
    if (argc == 2 && std::string_view(argv[1]) == "--help") return {.help = true};
    for (int i = 1; i < argc; ++i)
    {
        const std::string_view arg = argv[i];
        if (arg == "--status" && !result.status) result.status = true;
        else if (arg == "--watch-pid" && !result.watch && i + 1 < argc)
            result.watch = static_cast<pid_t>(number(argv[++i], INT32_MAX));
        else if (arg == "--max-duration" && !result.maximum && i + 1 < argc)
        {
            std::string_view value = argv[++i];
            uint32_t multiplier = 1;
            if (!value.empty() && value.back() >= 'a' && value.back() <= 'z')
            {
                const auto unit = value.back();
                multiplier = unit == 's'   ? 1
                             : unit == 'm' ? 60
                             : unit == 'h' ? 3600
                             : unit == 'd' ? 86400
                                           : 0;
                need(multiplier != 0, "duration needs seconds or an s, m, h or d suffix");
                value.remove_suffix(1);
            }
            result.maximum = number(value, 31536000 / multiplier) * multiplier;
            need(result.maximum > 0, "maximum duration must be positive");
        }
        else fail("usage: craft-maintain --watch-pid PID [--max-duration 21d] [--status]");
    }
    need(result.watch > 0 && !(result.status && result.maximum), "provide --watch-pid PID");
    return result;
}

// Follow one process without PID-reuse races. A pidfd reports the exit through poll(); kernels without
// pidfd_open (RHEL 8) get a descriptor for /proc/<pid>, which names that exact process and is checked each
// second.
struct Watch
{
    Fd fd;
    bool pollable = true;
};

inline bool exited(const Watch &watch)
{
    if (watch.pollable)
    {
        pollfd descriptor{watch.fd.get(), POLLIN, 0};
        int rc;
        do
            rc = poll(&descriptor, 1, 0);
        while (rc < 0 && errno == EINTR);
        sysneed(rc >= 0, "poll watched process");
        return descriptor.revents != 0;
    }

    // The directory outlives a zombie, so read the state that follows the parenthesized command name.
    std::array<char, 512> buffer{};
    const Fd stat(openat(watch.fd.get(), "stat", O_RDONLY | O_CLOEXEC));
    ssize_t count;
    do
        count = stat.get() < 0 ? 0 : read(stat.get(), buffer.data(), buffer.size());
    while (count < 0 && errno == EINTR);
    const std::string_view text(buffer.data(), count > 0 ? static_cast<size_t>(count) : 0);
    const auto name_end = text.rfind(')');
    return name_end == text.npos || name_end + 2 >= text.size() || text[name_end + 2] == 'Z' ||
           text[name_end + 2] == 'X';
}

inline Watch watch_process(pid_t pid, uid_t uid, bool pidfd = CRAFT_USE_PIDFD)
{
    // Hold a reference to the process before detaching, then verify its real Linux identity.
    Watch watch{Fd(pidfd ? static_cast<int>(syscall(SYS_pidfd_open, pid, 0)) : -1)};
    watch.pollable = watch.fd.get() >= 0;
    Fd directory(open(std::format("/proc/{}", pid).c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    sysneed(directory.get() >= 0, "open watched process");
    const Fd status(openat(directory.get(), "status", O_RDONLY | O_CLOEXEC));
    sysneed(status.get() >= 0, "read watched process identity");
    const auto bytes = read_all(status.get(), 65536);
    const std::string_view text(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    uint64_t real = UINT64_MAX;
    if (const auto pos = text.find("\nUid:\t"); pos != text.npos)
        std::from_chars(text.data() + pos + 6, text.data() + text.size(), real);
    if (!watch.pollable) watch.fd = std::move(directory);
    need(real == uid && !exited(watch), "watched process must be live and belong to the caller");
    return watch;
}

enum class Wake
{
    Timeout,
    Interrupted,
    Exited,
    Readable
};

// Wait until the watched process exits, `other` becomes readable (pass -1 for none), a signal arrives or the
// time passes. An exit takes precedence over a readable descriptor.
inline Wake wait_for(const Watch &watch, int other, Clock::time_point until)
{
    for (;;)
    {
        if (!watch.pollable && exited(watch)) return Wake::Exited;
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now()).count();
        if (left <= 0) return Wake::Timeout;
        std::array<pollfd, 2> descriptors{
            {{watch.pollable ? watch.fd.get() : -1, POLLIN, 0}, {other, POLLIN, 0}}};
        const int rc = poll(descriptors.data(),
                            descriptors.size(),
                            static_cast<int>(std::min<int64_t>(left, watch.pollable ? INT32_MAX : 1000)));
        if (rc < 0 && errno == EINTR) return Wake::Interrupted;
        sysneed(rc >= 0, "wait for watched process");
        if (descriptors[0].revents) return Wake::Exited;
        if (descriptors[1].revents) return Wake::Readable;
    }
}

enum class Action
{
    Idle,
    Renew,
    Enroll
};

struct Schedule
{
    Action action;
    uint32_t delay = 900;
};

inline Schedule schedule(const krb5_creds *tgt, time_t now)
{
    if (!tgt || tgt->times.endtime <= now) return {Action::Enroll};
    const int64_t life = static_cast<int64_t>(tgt->times.endtime) - start_time(tgt->times);
    need(life > 0, "invalid cached ticket lifetime");
    const int64_t margin = std::clamp(life / 5, int64_t{1}, int64_t{7200});
    const int64_t remaining = static_cast<int64_t>(tgt->times.endtime) - now;
    const bool renewable = (tgt->ticket_flags & TKT_FLG_RENEWABLE) != 0;
    const bool extendible = renewable && tgt->times.renew_till > tgt->times.endtime;
    int64_t next = remaining - margin;

    // Keep usable credentials renewed even while fresh enrollment is unavailable or backing off.
    if (extendible && next <= 0) return {Action::Renew};

    // Use the actual absolute renewal deadline, with proportional headroom for shorter grants.
    if (renewable)
    {
        const int64_t window = static_cast<int64_t>(tgt->times.renew_till) - tgt->times.authtime;
        const int64_t renewal_margin = std::clamp(window / 7, int64_t{1}, int64_t{86400});
        const int64_t renew_remaining = static_cast<int64_t>(tgt->times.renew_till) - now;
        if (renew_remaining <= renewal_margin)
            return {Action::Enroll,
                    extendible ? static_cast<uint32_t>(std::clamp(next, int64_t{1}, int64_t{900})) : 900U};
        next = std::min(next, renew_remaining - renewal_margin);
    }
    if (remaining <= margin) return {Action::Enroll};
    return {Action::Idle, static_cast<uint32_t>(std::clamp(next, int64_t{1}, int64_t{900}))};
}

inline void validate_cached_tgt(
    krb5_context ctx, const krb5_creds &tgt, krb5_principal client, krb5_principal server, time_t now)
{
    const int64_t start = start_time(tgt.times);
    need(krb5_principal_compare(ctx, tgt.client, client) && krb5_principal_compare(ctx, tgt.server, server) &&
             (tgt.ticket_flags & TKT_FLG_PRE_AUTH) && !(tgt.ticket_flags & PROHIBITED_TKT_FLAGS) &&
             tgt.times.authtime > 0 && start >= tgt.times.authtime && start <= now + 300 &&
             tgt.times.endtime > start &&
             ((tgt.ticket_flags & TKT_FLG_RENEWABLE) ? tgt.times.renew_till >= tgt.times.endtime
                                                     : tgt.times.renew_till == 0),
         "cached TGT identity, flags or times are invalid");
    require_aes_key(tgt.keyblock);
    (void)ticket_enctype(ctx, tgt.ticket);
}

inline void
validate_renewed_tgt(krb5_context ctx, const krb5_creds &previous, const krb5_creds &renewed, time_t now)
{
    validate_cached_tgt(ctx, renewed, previous.client, previous.server, now);
    const int64_t granted = previous.times.endtime - start_time(previous.times);
    need((previous.ticket_flags & TKT_FLG_RENEWABLE) && (renewed.ticket_flags & TKT_FLG_RENEWABLE) &&
             renewed.times.authtime == previous.times.authtime &&
             renewed.times.renew_till <= previous.times.renew_till && renewed.times.endtime > now &&
             renewed.times.endtime > previous.times.endtime &&
             renewed.times.endtime - start_time(renewed.times) <= granted + 5 &&
             renewed.times.endtime <= now + granted + 5,
         "renewed TGT exceeds its original lifetime/window or does not extend validity");
}

inline Bytes renewed_cache(krb5_context ctx, krb5_ccache source, krb5_creds &renewed, time_t now)
{
    auto bytes = file_cache(ctx, renewed);
    ScopeExit erase([&]() noexcept { wipe(bytes); });
    krb5_cc_cursor cursor{};
    krb_check(ctx, krb5_cc_start_seq_get(ctx, source, &cursor), "iterate existing cache");
    ScopeExit finish([&]() noexcept { krb5_cc_end_seq_get(ctx, source, &cursor); });

    // Retain usable service/configuration credentials while replacing the single local TGT.
    for (size_t count = 0;; ++count)
    {
        need(count < 4096, "too many credentials in cache");
        krb5_creds credential{};
        ScopeExit free([&]() noexcept { krb5_free_cred_contents(ctx, &credential); });
        const auto code = krb5_cc_next_cred(ctx, source, &cursor, &credential);
        if (code == KRB5_CC_END) break;
        krb_check(ctx, code, "read cached credential");
        if (!krb5_principal_compare(ctx, credential.client, renewed.client) ||
            krb5_principal_compare(ctx, credential.server, renewed.server))
            continue;
        if (credential.times.endtime > now || krb5_is_config_principal(ctx, credential.server))
            append_cache_credential(ctx, bytes, credential);
    }
    erase.release();
    return bytes;
}

// The outcome of one maintenance operation, passed from its process to the daemon as a single pipe write.
struct Result
{
    int64_t end = 0, renew = 0;
    uint32_t delay = 900, retry = 0;
    bool success = false;
    char principal[384]{}, error[512]{};
};

inline void set_text(std::span<char> field, std::string_view text)
{
    std::snprintf(field.data(), field.size(), "%.*s", static_cast<int>(text.size()), text.data());
}

// Invoke the fixed issuer with an empty environment, keeping a bounded prefix of its diagnostics.
inline void enroll()
{
    const Fd binary = root_open(LAUNCHER, Trusted::Launcher);
    Pipe diagnostics = make_pipe();
    Child issuer(fork_child(
        [&]() -> int
        {
            {
                const Fd null(open("/dev/null", O_RDWR));
                sysneed(null.get() >= 0 && dup2(null.get(), STDIN_FILENO) >= 0 &&
                            dup2(null.get(), STDOUT_FILENO) >= 0 &&
                            dup2(diagnostics.writer.get(), STDERR_FILENO) >= 0,
                        "issuer standard streams");
            }
            keep_only({binary.get()});
            const char *args[] = {LAUNCHER, nullptr};
            char *environment[] = {nullptr};
            fexecve(3, const_cast<char **>(args), environment);
            sysfail("exec issuer");
        },
        "craft-maintain"));
    diagnostics.writer = Fd();
    std::string text;
    std::array<char, 4096> buffer{};
    for (;;)
    {
        const auto count = read(diagnostics.reader.get(), buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        text.append(buffer.data(), std::min(static_cast<size_t>(count), 8192 - text.size()));
    }
    if (!issuer.wait()) fail("fresh credential acquisition failed: " + trim(text));
}

inline void update(const Account &caller, const std::string &expected, Result &result)
{
    const Fd home = caller_home(caller), maintenance = cache_lock(home.get(), MAINTAIN_LOCK);
    const Account current = lookup_uid(caller.uid);
    need(current.name == caller.name && current.home == caller.home, "runtime UID/name/home changed");
    KrbContext context;
    krb_check(nullptr, krb5_init_secure_context(out(context)), "initialize system Kerberos configuration");
    const auto ctx = context.get();

    // Serialize renewals with every CRAFT publication; release that lock before invoking the issuer.
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        Fd lock = cache_lock(home.get(), CACHE_LOCK);
        const Fd file = open_private(home.get(), CACHE_NAME, O_RDONLY, "credential cache");
        auto cache = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
        KrbPrincipal client(nullptr, {ctx}), server(nullptr, {ctx});
        krb5_creds tgt{};
        ScopeExit free([&]() noexcept { krb5_free_cred_contents(ctx, &tgt); });
        bool found = false;
        if (file.get() >= 0)
        {
            // Read the validated inode itself, so the cache cannot be swapped between the check and its use.
            const auto name = std::format("FILE:/proc/self/fd/{}", file.get());
            krb_check(ctx, krb5_cc_resolve(ctx, name.c_str(), out(cache)), "open cache for Kerberos");
            krb_check(ctx, krb5_cc_get_principal(ctx, cache.get(), out(client)), "read cache principal");
            const auto component = krb5_princ_component(ctx, client.get(), 0);
            const auto realm = krb5_princ_realm(ctx, client.get());
            need(krb5_princ_size(ctx, client.get()) == 1 && component && realm && realm->length &&
                     std::string_view(component->data, component->length) == caller.name,
                 "cache principal does not match the Linux caller");
            auto text = krb_owner<char, krb5_free_unparsed_name>(ctx);
            krb_check(ctx, krb5_unparse_name(ctx, client.get(), out(text)), "format cache principal");
            need(expected.empty() || expected == text.get(), "maintained principal changed");
            need(std::strlen(text.get()) < sizeof(result.principal), "cache principal is too long");
            set_text(result.principal, text.get());
            server = tgs_principal(ctx, std::string_view(realm->data, realm->length));
            krb5_creds match{};
            match.client = client.get();
            match.server = server.get();
            const auto code = krb5_cc_retrieve_cred(ctx, cache.get(), 0, &match, &tgt);
            if (code != KRB5_CC_NOTFOUND) krb_check(ctx, code, "read cached TGT");
            found = code == 0;
            if (found)
            {
                validate_cached_tgt(ctx, tgt, client.get(), server.get(), time(nullptr));
                result.end = tgt.times.endtime;
                result.renew = tgt.times.renew_till;
            }
        }
        const auto plan = schedule(found ? &tgt : nullptr, time(nullptr));
        result.delay = plan.delay;
        if (plan.action == Action::Idle)
        {
            unlinkat(home.get(), RETRY_STATE, 0);
            result.success = true;
            return;
        }
        if (plan.action == Action::Enroll)
        {
            need(attempt == 0, "fresh enrollment returned no sufficiently usable TGT");

            // Share enrollment backoff across jobs so outages cannot create a certificate storm.
            const Fd retry = cache_lock(home.get(), RETRY_STATE);
            uint64_t next = 0;
            uint32_t failures = 0;
            if (const auto state = read_record(retry.get()); !state.empty())
            {
                std::istringstream input(state);
                need(static_cast<bool>(input >> next >> failures) && failures <= 7,
                     "invalid enrollment retry state");
            }
            const auto now = static_cast<uint64_t>(time(nullptr));
            if (next > now)
            {
                result.retry = static_cast<uint32_t>(std::min(next - now, uint64_t{plan.delay}));
                fail(std::format("fresh enrollment retry is delayed until Unix {}", next));
            }
            result.retry = std::min(3600U, 60U << failures);
            write_record(retry.get(), std::format("{} {}", now + result.retry, std::min(failures + 1, 7U)));
            result.retry = std::min(result.retry, plan.delay);
            lock = Fd();
            enroll();
            result.retry = 0;
            syslog(
                LOG_NOTICE, "obtained fresh credentials for uid=%lu", static_cast<unsigned long>(caller.uid));
            continue;
        }

        // Renew using the cached session key; a failed renewal never falls back to certificate enrollment.
        krb5_creds renewed{};
        ScopeExit free_renewed([&]() noexcept { krb5_free_cred_contents(ctx, &renewed); });
        krb_check(
            ctx, krb5_get_renewed_creds(ctx, &renewed, client.get(), cache.get(), nullptr), "renew user TGT");
        validate_renewed_tgt(ctx, tgt, renewed, time(nullptr));
        auto bytes = renewed_cache(ctx, cache.get(), renewed, time(nullptr));
        ScopeExit erase([&]() noexcept { wipe(bytes); });
        publish_cache(home.get(), bytes);
        result.end = renewed.times.endtime;
        result.renew = renewed.times.renew_till;
        const auto next = schedule(&renewed, time(nullptr));
        result.delay = next.action == Action::Idle ? next.delay : 1;
        result.success = true;
        syslog(LOG_NOTICE,
               "renewed TGT for uid=%lu expiry=%lld",
               static_cast<unsigned long>(caller.uid),
               static_cast<long long>(result.end));
        return;
    }
}

inline std::string status_name(pid_t watch)
{
    return std::format("{}.maintain.{}.status", CACHE_NAME, watch);
}

inline void
write_status(const Account &caller, pid_t watch, std::string_view state, const Result &result, uint32_t delay)
{
    const auto text = std::format("job_pid={}\nmaintainer_pid={}\nstate={}\ntgt_expires={}\nrenew_until={}\n"
                                  "next_check={}\nlast_error={}\n",
                                  watch,
                                  getpid(),
                                  state,
                                  result.end,
                                  result.renew,
                                  delay ? time(nullptr) + delay : 0,
                                  result.error);
    replace_file(caller_home(caller).get(), status_name(watch), byte_view(text), false);
}

// Status files outlive their job so it can be inspected afterwards; remove those, and temporaries orphaned by
// a crash, once they are a week old. A live maintainer rewrites its status at least hourly.
inline void prune_stale_files(int home, time_t now, time_t age = 7 * 86400) noexcept
{
    const int copy = openat(home, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *listing = copy < 0 ? nullptr : fdopendir(copy);
    if (!listing)
    {
        if (copy >= 0) ::close(copy);
        return;
    }
    const auto prefix = std::string(CACHE_NAME) + ".", status_prefix = prefix + "maintain.";
    while (const dirent *entry = readdir(listing))
    {
        const std::string_view name = entry->d_name;
        const bool status = name.starts_with(status_prefix) && name.ends_with(".status");
        if (!status && !(name.starts_with(prefix) && name.find(".tmp.") != name.npos)) continue;
        struct stat st
        {
        };
        if (fstatat(home, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode) &&
            st.st_uid == geteuid() && now - st.st_mtime > age)
            unlinkat(home, entry->d_name, 0);
    }
    closedir(listing);
}

// Sleep until the next check is due; false when the job ended, a stop was requested or the deadline passed.
inline bool idle(const Watch &watch, uint32_t seconds, Clock::time_point deadline)
{
    const auto until = std::min(Clock::now() + std::chrono::seconds(seconds), deadline);
    while (!stopping && Clock::now() < until)
        if (wait_for(watch, -1, until) == Wake::Exited) return false;
    return !stopping && Clock::now() < deadline && !exited(watch);
}

// Run one bounded operation in its own process, so a hung library call can be cancelled with its descendants.
inline Result
run_update(const Account &caller, const std::string &expected, const Watch &watch, Clock::time_point deadline)
{
    Pipe channel = make_pipe(O_NONBLOCK);
    const pid_t maintainer = getpid();
    const auto operate = [&]
    {
        Result result;
        set_text(result.principal, expected);
        try
        {
            sysneed(setpgid(0, 0) == 0 && prctl(PR_SET_PDEATHSIG, SIGKILL) == 0,
                    "maintenance child lifecycle");
            need(getppid() == maintainer, "maintainer disappeared");
            signal(SIGTERM, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            update(caller, expected, result);
        }
        catch (const std::exception &error)
        {
            set_text(result.error, sanitize_ascii(error.what()));
        }
        const auto count = write(channel.writer.get(), &result, sizeof(result));
        return count == static_cast<ssize_t>(sizeof(result)) ? 0 : 1;
    };
    Child operation(fork_child(operate, "craft-maintain"), true);
    channel.writer = Fd();
    if (setpgid(operation.pid(), operation.pid()) != 0)
        need(errno == EACCES || errno == ESRCH, "set maintenance process group");
    const auto until = std::min(Clock::now() + std::chrono::seconds(150), deadline);
    while (!stopping && Clock::now() < until)
    {
        const auto wake = wait_for(watch, channel.reader.get(), until);
        if (wake == Wake::Exited) break;
        if (wake != Wake::Readable) continue;
        Result result;
        need(read(channel.reader.get(), &result, sizeof(result)) == static_cast<ssize_t>(sizeof(result)),
             "maintenance operation returned no complete result");
        need(operation.wait(), "maintenance operation failed");
        result.principal[sizeof(result.principal) - 1] = result.error[sizeof(result.error) - 1] = '\0';
        return result;
    }
    fail("maintenance operation timed out or the watched job ended");
}

// The detached loop: keep the cache usable until the job ends, a stop is requested or the deadline passes.
// `ready` receives one byte once the first operation shows whether a usable cache exists.
inline void serve(const Account &caller, const Options &option, const Watch &watch, int ready)
{
    Result last;
    const auto deadline =
        option.maximum ? Clock::now() + std::chrono::seconds(option.maximum) : Clock::time_point::max();
    bool announced = false;
    uint32_t failures = 0;
    std::string expected;
    ScopeExit close_ready(
        [&]() noexcept
        {
            if (ready >= 0) close(ready);
        });
    openlog("craft-maintain", LOG_PID, LOG_AUTHPRIV);
    ScopeExit close_log([]() noexcept { closelog(); });
    signal(SIGTERM, [](int) { stopping = 1; });
    signal(SIGINT, [](int) { stopping = 1; });

    // A start command that has already gone must surface as a write error, not end the daemon silently.
    signal(SIGPIPE, SIG_IGN);
    try
    {
        prune_stale_files(caller_home(caller).get(), time(nullptr));
        while (!stopping && Clock::now() < deadline && !exited(watch))
        {
            Result result;
            try
            {
                result = run_update(caller, expected, watch, deadline);
            }
            catch (const std::exception &error)
            {
                result.end = last.end;
                result.renew = last.renew;
                set_text(result.principal, expected);
                set_text(result.error, error.what());
            }
            if (stopping || Clock::now() >= deadline || exited(watch)) break;
            last = result;
            if (!expected.empty()) need(expected == result.principal, "maintenance identity changed");
            else if (result.principal[0]) expected = result.principal;
            const bool usable = result.end > time(nullptr) && result.principal[0];
            if (result.success) failures = 0;
            else syslog(LOG_WARNING, "%s", result.error);
            const uint32_t delay = result.success ? result.delay
                                   : result.retry ? result.retry
                                                  : std::min(300U, 30U << std::min(failures++, 4U)) +
                                                        static_cast<uint32_t>(getpid() % 11);
            write_status(caller,
                         option.watch,
                         result.success ? "ready"
                         : usable       ? "retrying"
                                        : "expired",
                         result,
                         delay);

            // A startup call succeeds only with a usable cache and a functioning detached loop.
            if (!announced)
            {
                const unsigned char success = usable ? 1 : 0;
                write_all(ready, {&success, 1});
                close(std::exchange(ready, -1));
                if (!usable) break;
                announced = true;
            }
            if (!idle(watch, delay, deadline)) break;
        }
    }
    catch (const std::exception &error)
    {
        set_text(last.error, error.what());
        syslog(LOG_ERR, "%s", last.error);
    }
    try
    {
        write_status(caller, option.watch, announced ? "stopped" : "failed", last, 0);
    }
    catch (const std::exception &error)
    {
        syslog(LOG_ERR, "%s", error.what());
    }
}

// Start the daemon in its own session and wait for it to report a usable cache.
inline void detach(const Account &caller, const Options &option, const Watch &watch)
{
    Pipe startup = make_pipe();
    Child intermediate(fork_child(
        [&]
        {
            sysneed(setsid() >= 0, "detach maintenance session");
            const pid_t background = fork();
            sysneed(background >= 0, "detach maintenance process");
            if (background > 0) return 0;

            // Replace the job's captured streams and drop every inherited descriptor but the lifecycle pair.
            {
                const Fd null(open("/dev/null", O_RDWR));
                sysneed(null.get() >= 0, "open detached standard streams");
                for (int fd = 0; fd < 3; ++fd)
                    sysneed(dup2(null.get(), fd) == fd, "detach job stream");
            }
            keep_only({watch.fd.get(), startup.writer.get()});
            sysneed(chdir("/") == 0, "detach working directory");
            signal(SIGHUP, SIG_IGN);
            serve(caller, option, Watch{Fd(3), watch.pollable}, 4);
            return 0;
        },
        "craft-maintain"));
    startup.writer = Fd();
    need(intermediate.wait(), "background startup failed");
    const auto until = Clock::now() + std::chrono::seconds(160);
    Wake wake;
    do
        wake = wait_for(watch, startup.reader.get(), until);
    while (wake == Wake::Interrupted);
    unsigned char success = 0;
    need(wake == Wake::Readable && read(startup.reader.get(), &success, 1) == 1 && success == 1,
         "maintenance startup failed; inspect craft-maintain --status --watch-pid PID and AUTHPRIV logs");
}

} // namespace craft::maintain

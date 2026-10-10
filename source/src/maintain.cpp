// Detached, unprivileged credential maintenance for an explicitly watched batch process.
#include "resources.hpp"
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <chrono>
#include <iostream>

namespace craft::maintain
{
using Clock = std::chrono::steady_clock;
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
                multiplier = unit == 's' ? 1 : unit == 'm' ? 60 : unit == 'h' ? 3600 : unit == 'd' ? 86400 : 0;
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

inline bool exited(int pidfd)
{
    pollfd descriptor{pidfd, POLLIN, 0};
    int rc;
    do rc = poll(&descriptor, 1, 0); while (rc < 0 && errno == EINTR);
    sysneed(rc >= 0, "poll watched process");
    return descriptor.revents != 0;
}

inline Fd watch_process(pid_t pid, uid_t uid)
{
    // Hold a process reference before detaching and verify its real Linux identity.
    Fd descriptor(static_cast<int>(syscall(SYS_pidfd_open, pid, 0)));
    sysneed(descriptor.get() >= 0, "open watched process (Linux 5.3 or newer required)");
    const Fd status(open(std::format("/proc/{}/status", pid).c_str(), O_RDONLY | O_CLOEXEC));
    sysneed(status.get() >= 0, "read watched process identity");
    const auto bytes = read_all(status.get(), 65536);
    const std::string_view text(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    bool matches = false;
    const auto pos = text.find("\nUid:\t");
    if (pos != text.npos)
    {
        uint64_t real = UINT64_MAX;
        const auto start = pos + 6;
        const auto [ptr, ec] = std::from_chars(text.data() + start, text.data() + text.size(), real);
        matches = (ec == std::errc{} && real == uid);
    }
    need(matches && !exited(descriptor.get()), "watched process must be live and belong to the caller");
    return descriptor;
}

enum class Action { Idle, Renew, Enroll };

struct Schedule
{
    Action action;
    uint32_t delay = 900;
};

inline Schedule schedule(const krb5_creds *tgt, time_t now)
{
    if (!tgt || tgt->times.endtime <= now) return {Action::Enroll};
    const int64_t start = tgt->times.starttime ? tgt->times.starttime : tgt->times.authtime;
    const int64_t life = static_cast<int64_t>(tgt->times.endtime) - start;
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
            return {Action::Enroll, extendible
                ? static_cast<uint32_t>(std::clamp(next, int64_t{1}, int64_t{900})) : 900U};
        next = std::min(next, renew_remaining - renewal_margin);
    }
    if (remaining <= margin) return {Action::Enroll};
    return {Action::Idle, static_cast<uint32_t>(std::clamp(next, int64_t{1}, int64_t{900}))};
}

inline void check(krb5_context ctx, krb5_error_code code, std::string_view operation)
{
    krb_check(ctx, code, operation);
}

inline void validate_cached_tgt(krb5_context ctx, const krb5_creds &tgt,
                                krb5_principal client, krb5_principal server, time_t now)
{
    const int64_t start = tgt.times.starttime ? tgt.times.starttime : tgt.times.authtime;
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

inline void validate_renewed_tgt(krb5_context ctx, const krb5_creds &previous,
                                 const krb5_creds &renewed, time_t now)
{
    validate_cached_tgt(ctx, renewed, previous.client, previous.server, now);
    const int64_t old_start = previous.times.starttime ? previous.times.starttime : previous.times.authtime;
    const int64_t start = renewed.times.starttime ? renewed.times.starttime : renewed.times.authtime;
    need((previous.ticket_flags & TKT_FLG_RENEWABLE) && (renewed.ticket_flags & TKT_FLG_RENEWABLE) &&
             renewed.times.authtime == previous.times.authtime &&
             renewed.times.renew_till <= previous.times.renew_till && renewed.times.endtime > now &&
             renewed.times.endtime > previous.times.endtime &&
             static_cast<int64_t>(renewed.times.endtime) - start <= previous.times.endtime - old_start + 5 &&
             static_cast<int64_t>(renewed.times.endtime) <= now + previous.times.endtime - old_start + 5,
         "renewed TGT exceeds its original lifetime/window or does not extend validity");
}

inline Bytes renewed_cache(krb5_context ctx, krb5_ccache source, krb5_creds &renewed, time_t now)
{
    auto bytes = file_cache(ctx, renewed);
    ScopeExit erase([&]() noexcept { wipe(bytes); });
    krb5_cc_cursor cursor{};
    check(ctx, krb5_cc_start_seq_get(ctx, source, &cursor), "iterate existing cache");
    ScopeExit finish([&]() noexcept { krb5_cc_end_seq_get(ctx, source, &cursor); });

    // Retain usable service/configuration credentials while replacing the single local TGT.
    for (size_t count = 0; ; ++count)
    {
        need(count < 4096, "too many credentials in cache");
        krb5_creds credential{};
        ScopeExit free([&]() noexcept { krb5_free_cred_contents(ctx, &credential); });
        const auto code = krb5_cc_next_cred(ctx, source, &cursor, &credential);
        if (code == KRB5_CC_END) break;
        check(ctx, code, "read cached credential");
        if (!krb5_principal_compare(ctx, credential.client, renewed.client) ||
            krb5_principal_compare(ctx, credential.server, renewed.server)) continue;
        if (credential.times.endtime > now || krb5_is_config_principal(ctx, credential.server))
            append_cache_credential(ctx, bytes, credential);
    }
    erase.release();
    return bytes;
}

struct Result
{
    int64_t end = 0, renew = 0;
    uint32_t delay = 900, retry = 0;
    bool success = false;
    char principal[384]{}, error[512]{};
};

inline void enroll()
{
    // Invoke the fixed issuer with a clean environment, capturing only its diagnostic stream.
    Fd binary = root_open(LAUNCHER);
    std::array<int, 2> pipe{};
    sysneed(pipe2(pipe.data(), O_CLOEXEC) == 0, "issuer diagnostic pipe");
    Fd reader(pipe[0]), writer(pipe[1]);
    const pid_t child = fork();
    sysneed(child >= 0, "start issuer");
    if (child == 0)
    {
        const Fd null(open("/dev/null", O_RDWR));
        if (null.get() < 0 || dup2(null.get(), STDIN_FILENO) < 0 ||
            dup2(null.get(), STDOUT_FILENO) < 0 || dup2(writer.get(), STDERR_FILENO) < 0) _exit(1);
        if (binary.get() != 3 && dup3(binary.get(), 3, O_CLOEXEC) < 0) _exit(1);
        close_from(4);
        char path[] = "PATH=/usr/bin:/bin", lang[] = "LANG=C";
        char *args[] = {const_cast<char *>(LAUNCHER), nullptr};
        char *env[] = {path, lang, nullptr};
        fexecve(3, args, env);
        _exit(1);
    }
    ScopeExit cleanup([&]() noexcept
    {
        kill(child, SIGKILL);
        waitpid_retry(child, nullptr);
    });
    writer = Fd();
    const auto diagnostics = read_all(reader.get(), 8192);
    int status{};
    const pid_t waited = waitpid_retry(child, &status, 0);
    sysneed(waited == child, "wait for issuer");
    cleanup.release();
    need(WIFEXITED(status) && WEXITSTATUS(status) == 0,
         "fresh credential acquisition failed: " + trim(std::string(diagnostics.begin(), diagnostics.end())));
}

inline void update(const Account &caller, const std::string &expected, Result &result)
{
    const Fd home = caller_home(caller), maintenance = cache_lock(home.get(), MAINTAIN_LOCK);
    const Account current = lookup_uid(caller.uid);
    need(current.name == caller.name && current.home == caller.home, "runtime UID/name/home changed");
    KrbContext context;
    check(nullptr, krb5_init_secure_context(out(context)), "initialize system Kerberos configuration");
    const auto ctx = context.get();

    // Serialize renewals with every CRAFT publication; release that lock before invoking the issuer.
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        Fd lock = cache_lock(home.get(), CACHE_LOCK);
        Fd file(openat(home.get(), CACHE_NAME, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
        sysneed(file.get() >= 0 || errno == ENOENT, "open user credential cache");
        auto cache = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
        auto client = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
        auto server = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
        krb5_creds tgt{};
        ScopeExit free([&]() noexcept { krb5_free_cred_contents(ctx, &tgt); });
        bool found = false;
        if (file.get() >= 0)
        {
            struct stat st{};
            sysneed(fstat(file.get(), &st) == 0, "stat user credential cache");
            need(S_ISREG(st.st_mode) && st.st_uid == caller.uid && st.st_nlink == 1 &&
                     !(st.st_mode & 0077) && st.st_size >= 0 && st.st_size <= static_cast<off_t>(MAX_BLOB),
                 "credential cache must be caller-owned, regular, private and within the size limit");
            const auto name = std::format("FILE:/proc/self/fd/{}", file.get());
            check(ctx, krb5_cc_resolve(ctx, name.c_str(), out(cache)), "open cache for Kerberos");
            check(ctx, krb5_cc_get_principal(ctx, cache.get(), out(client)), "read cache principal");
            const auto component = krb5_princ_component(ctx, client.get(), 0);
            const auto realm = krb5_princ_realm(ctx, client.get());
            need(krb5_princ_size(ctx, client.get()) == 1 && component && realm && realm->length &&
                     std::string_view(component->data, component->length) == caller.name,
                 "cache principal does not match the Linux caller");
            auto text = krb_owner<char, krb5_free_unparsed_name>(ctx);
            check(ctx, krb5_unparse_name(ctx, client.get(), out(text)), "format cache principal");
            need(expected.empty() || expected == text.get(), "maintained principal changed");
            need(std::strlen(text.get()) < sizeof(result.principal), "cache principal is too long");
            std::strcpy(result.principal, text.get());
            const auto tgs = "krbtgt/" + std::string(realm->data, realm->length) + "@" +
                             std::string(realm->data, realm->length);
            check(ctx, krb5_parse_name(ctx, tgs.c_str(), out(server)), "parse local TGT server");
            krb5_creds match{};
            match.client = client.get();
            match.server = server.get();
            const auto code = krb5_cc_retrieve_cred(ctx, cache.get(), 0, &match, &tgt);
            if (code != KRB5_CC_NOTFOUND) check(ctx, code, "read cached TGT");
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
            unlinkat(home.get(), ".krb5cc_craft.maintain.retry", 0);
            result.success = true;
            return;
        }
        if (plan.action == Action::Enroll)
        {
            need(attempt == 0, "fresh enrollment returned no sufficiently usable TGT");

            // Share enrollment backoff across jobs so outages cannot create a certificate storm.
            const Fd retry = cache_lock(home.get(), ".krb5cc_craft.maintain.retry");
            const auto bytes = read_all(retry.get(), 64);
            uint64_t next = 0;
            uint32_t failures = 0;
            if (!bytes.empty())
            {
                std::istringstream input(std::string(bytes.begin(), bytes.end()));
                need(static_cast<bool>(input >> next >> failures) && failures <= 7, "invalid enrollment retry state");
            }
            const auto now = static_cast<uint64_t>(time(nullptr));
            if (next > now)
            {
                result.retry = static_cast<uint32_t>(std::min(next - now, uint64_t{plan.delay}));
                fail(std::format("fresh enrollment retry is delayed until Unix {}", next));
            }
            result.retry = std::min(3600U, 60U << failures);
            const auto text = std::format("{} {}\n", now + result.retry, std::min(failures + 1, 7U));
            write_truncated(retry.get(), byte_view(text));
            result.retry = std::min(result.retry, plan.delay);
            lock = Fd();
            enroll();
            result.retry = 0;
            syslog(LOG_NOTICE, "obtained fresh credentials for uid=%lu", static_cast<unsigned long>(caller.uid));
            continue;
        }

        // Renew using the cached session key; a failed renewal never falls back to certificate enrollment.
        krb5_creds renewed{};
        ScopeExit free_renewed([&]() noexcept { krb5_free_cred_contents(ctx, &renewed); });
        check(ctx, krb5_get_renewed_creds(ctx, &renewed, client.get(), cache.get(), nullptr), "renew user TGT");
        validate_renewed_tgt(ctx, tgt, renewed, time(nullptr));
        auto bytes = renewed_cache(ctx, cache.get(), renewed, time(nullptr));
        ScopeExit erase([&]() noexcept { wipe(bytes); });
        publish_cache(caller, bytes);
        result.end = renewed.times.endtime;
        result.renew = renewed.times.renew_till;
        const auto next = schedule(&renewed, time(nullptr));
        result.delay = next.action == Action::Idle ? next.delay : 1;
        result.success = true;
        syslog(LOG_NOTICE, "renewed TGT for uid=%lu expiry=%lld",
               static_cast<unsigned long>(caller.uid), static_cast<long long>(result.end));
        return;
    }
}

inline std::string status_name(pid_t watch)
{
    return std::format("{}.maintain.{}.status", CACHE_NAME, watch);
}

inline void write_status(const Account &caller, pid_t watch, std::string_view state,
                         const Result &result, uint32_t delay)
{
    const Fd home = caller_home(caller);
    const auto name = status_name(watch), temporary = name + ".tmp." + random_hex();
    const Fd file(openat(home.get(), temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    sysneed(file.get() >= 0, "create maintenance status");
    ScopeExit cleanup([&]() noexcept { unlinkat(home.get(), temporary.c_str(), 0); });
    const auto text = std::format("job_pid={}\nmaintainer_pid={}\nstate={}\ntgt_expires={}\nrenew_until={}\n"
                                  "next_check={}\nlast_error={}\n",
                                  watch, getpid(), state, result.end, result.renew,
                                  delay ? time(nullptr) + delay : 0, result.error);
    write_all(file.get(), byte_view(text));
    sysneed(renameat(home.get(), temporary.c_str(), home.get(), name.c_str()) == 0, "publish maintenance status");
    cleanup.release();
}

inline bool pause(int watch, uint32_t seconds, Clock::time_point deadline)
{
    const auto until = std::min(Clock::now() + std::chrono::seconds(seconds), deadline);
    while (!stopping && Clock::now() < until)
    {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now()).count();
        pollfd descriptor{watch, POLLIN, 0};
        const int rc = poll(&descriptor, 1, static_cast<int>(std::clamp(left, int64_t{1}, int64_t{INT32_MAX})));
        if (rc < 0 && errno == EINTR) continue;
        sysneed(rc >= 0, "wait for watched process");
        if (rc > 0) return false;
    }
    return !stopping && Clock::now() < deadline && !exited(watch);
}

inline Result run_update(const Account &caller, const std::string &expected,
                          int watch, Clock::time_point deadline)
{
    std::array<int, 2> pipe{};
    sysneed(pipe2(pipe.data(), O_CLOEXEC | O_NONBLOCK) == 0, "maintenance result pipe");
    Fd reader(pipe[0]), writer(pipe[1]);
    const pid_t parent = getpid(), child = fork();
    sysneed(child >= 0, "start maintenance operation");
    if (child == 0)
    {
        // Keep each bounded operation and its issuer descendants in a cancellable process group.
        Result result;
        std::snprintf(result.principal, sizeof(result.principal), "%s", expected.c_str());
        try
        {
            reader = Fd();
            sysneed(setpgid(0, 0) == 0 && prctl(PR_SET_PDEATHSIG, SIGKILL) == 0, "maintenance child lifecycle");
            need(getppid() == parent, "maintainer disappeared");
            signal(SIGTERM, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            update(caller, expected, result);
        }
        catch (const std::exception &error)
        {
            const auto clean = sanitize_ascii(error.what());
            std::snprintf(result.error, sizeof(result.error), "%s", clean.c_str());
        }
        const auto count = write(writer.get(), &result, sizeof(result));
        _exit(count == sizeof(result) ? 0 : 1);
    }
    writer = Fd();
    if (setpgid(child, child) != 0) need(errno == EACCES || errno == ESRCH, "set maintenance process group");
    ScopeExit cleanup([&]() noexcept
    {
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
        waitpid_retry(child, nullptr);
    });
    const auto until = std::min(Clock::now() + std::chrono::seconds(150), deadline);
    while (!stopping && Clock::now() < until && !exited(watch))
    {
        std::array<pollfd, 2> descriptors{{{watch, POLLIN, 0}, {reader.get(), POLLIN, 0}}};
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now()).count();
        const int rc = poll(descriptors.data(), descriptors.size(),
                            static_cast<int>(std::clamp(left, int64_t{1}, int64_t{INT32_MAX})));
        if (rc < 0 && errno == EINTR) continue;
        sysneed(rc >= 0, "wait for maintenance operation");
        if (descriptors[0].revents) break;
        if (!descriptors[1].revents) continue;
        Result result;
        const auto count = read(reader.get(), &result, sizeof(result));
        need(count == sizeof(result), "maintenance operation returned no complete result");
        int status{};
        const pid_t waited = waitpid_retry(child, &status, 0);
        sysneed(waited == child, "reap maintenance operation");
        cleanup.release();
        need(WIFEXITED(status) && WEXITSTATUS(status) == 0, "maintenance operation failed");
        return result;
    }
    fail("maintenance operation timed out or the watched job ended");
}

inline void daemon(const Account &caller, const Options &option, int watch, int ready)
{
    Result last;
    const auto deadline = option.maximum ? Clock::now() + std::chrono::seconds(option.maximum)
                                         : Clock::time_point::max();
    bool announced = false;
    uint32_t failures = 0;
    std::string expected;
    ScopeExit close_ready([&]() noexcept { if (ready >= 0) close(ready); });
    openlog("craft-maintain", LOG_PID, LOG_AUTHPRIV);
    ScopeExit close_log([]() noexcept { closelog(); });
    signal(SIGTERM, [](int) { stopping = 1; });
    signal(SIGINT, [](int) { stopping = 1; });
    try
    {
        while (!stopping && Clock::now() < deadline && !exited(watch))
        {
            Result result;
            try { result = run_update(caller, expected, watch, deadline); }
            catch (const std::exception &error)
            {
                result.end = last.end;
                result.renew = last.renew;
                std::snprintf(result.principal, sizeof(result.principal), "%s", expected.c_str());
                std::snprintf(result.error, sizeof(result.error), "%s", error.what());
            }
            if (stopping || Clock::now() >= deadline || exited(watch)) break;
            last = result;
            if (!expected.empty()) need(expected == result.principal, "maintenance identity changed");
            else if (result.principal[0]) expected = result.principal;
            const bool usable = result.end > time(nullptr) && result.principal[0];
            if (result.success) failures = 0;
            else syslog(LOG_WARNING, "%s", result.error);
            const uint32_t delay = result.success ? result.delay : result.retry ? result.retry
                : std::min(300U, 30U << std::min(failures++, 4U)) + static_cast<uint32_t>(getpid() % 11);
            const auto state = result.success ? "ready" : usable ? "retrying" : "expired";
            write_status(caller, option.watch, state, result, delay);

            // A startup call succeeds only with a usable cache and a functioning detached loop.
            if (!announced)
            {
                const unsigned char success = usable ? 1 : 0;
                write_all(ready, {&success, 1});
                close(ready);
                ready = -1;
                if (!usable) break;
                announced = true;
            }
            if (!pause(watch, delay, deadline)) break;
        }
    }
    catch (const std::exception &error)
    {
        std::snprintf(last.error, sizeof(last.error), "%s", error.what());
        syslog(LOG_ERR, "%s", last.error);
    }
    try { write_status(caller, option.watch, announced ? "stopped" : "failed", last, 0); }
    catch (const std::exception &error) { syslog(LOG_ERR, "%s", error.what()); }
}

inline void detach(const Account &caller, const Options &option, Fd watch)
{
    std::array<int, 2> pipe{};
    sysneed(pipe2(pipe.data(), O_CLOEXEC) == 0, "startup confirmation pipe");
    Fd reader(pipe[0]), writer(pipe[1]);
    const pid_t child = fork();
    sysneed(child >= 0, "start background maintainer");
    if (child == 0)
    {
        try
        {
            reader = Fd();
            sysneed(setsid() >= 0, "detach maintenance session");
            const pid_t background = fork();
            sysneed(background >= 0, "detach maintenance process");
            if (background > 0) _exit(0);

            // Close captured job streams and inherited descriptors before reporting startup completion.
            const Fd watch_copy(fcntl(watch.get(), F_DUPFD_CLOEXEC, 5));
            const Fd ready_copy(fcntl(writer.get(), F_DUPFD_CLOEXEC, 5));
            sysneed(watch_copy.get() >= 0 && ready_copy.get() >= 0, "retain lifecycle descriptors");
            const Fd null(open("/dev/null", O_RDWR));
            sysneed(null.get() >= 0, "open detached standard streams");
            for (int fd = 0; fd < 3; ++fd) sysneed(dup2(null.get(), fd) == fd, "detach job stream");
            sysneed(dup3(watch_copy.get(), 3, O_CLOEXEC) == 3 && dup3(ready_copy.get(), 4, O_CLOEXEC) == 4,
                    "install lifecycle descriptors");
            close_from(5);
            sysneed(chdir("/") == 0, "detach working directory");
            signal(SIGHUP, SIG_IGN);
            daemon(caller, option, 3, 4);
            _exit(0);
        }
        catch (const std::exception &)
        {
            _exit(1);
        }
    }
    writer = Fd();
    int status{};
    const pid_t waited = waitpid_retry(child, &status, 0);
    sysneed(waited == child, "reap startup process");
    need(WIFEXITED(status) && WEXITSTATUS(status) == 0, "background startup failed");
    std::array<pollfd, 2> descriptors{{{watch.get(), POLLIN, 0}, {reader.get(), POLLIN, 0}}};
    int rc;
    do rc = poll(descriptors.data(), descriptors.size(), 160000); while (rc < 0 && errno == EINTR);
    sysneed(rc >= 0, "wait for startup confirmation");
    unsigned char success = 0;
    need(rc > 0 && !descriptors[0].revents && read(reader.get(), &success, 1) == 1 && success == 1,
         "maintenance startup failed; inspect craft-maintain --status --watch-pid PID and AUTHPRIV logs");
}
} // namespace craft::maintain

#ifndef CRAFT_TEST
int main(int argc, char **argv)
{
    using namespace craft;
    try
    {
        const auto option = maintain::options(argc, argv);
        if (option.help)
        {
            std::cout << "Usage: craft-maintain --watch-pid PID [--max-duration 21d] [--status]\n"
                         "Start once as the batch user; stdout is the FILE cache name.\n"
                         "--status reads the latest status for that job, including after it ends.\n";
            return 0;
        }
        need(getuid() != 0 && getuid() == geteuid() && getgid() == getegid(),
             "run directly as the non-root batch user; never install craft-maintain setuid/setgid");
        no_core();
        const Account caller = lookup_uid(getuid());
        need(simple_name(caller.name) && caller.name != SERVICE_USER, "invalid maintenance caller");
        if (option.status)
        {
            const Fd home = caller_home(caller);
            const Fd file(openat(home.get(), maintain::status_name(option.watch).c_str(),
                                O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
            sysneed(file.get() >= 0, "open maintenance status");
            struct stat st{};
            sysneed(fstat(file.get(), &st) == 0, "stat maintenance status");
            need(S_ISREG(st.st_mode) && st.st_uid == caller.uid && !(st.st_mode & 0077), "unsafe status file");
            const auto bytes = read_all(file.get(), 8192);
            write_all(STDOUT_FILENO, bytes);
            return 0;
        }
        sigset_t empty;
        sigemptyset(&empty);
        sysneed(sigprocmask(SIG_SETMASK, &empty, nullptr) == 0, "reset maintenance signal mask");
        for (int signum : {SIGPIPE, SIGCHLD, SIGTERM, SIGINT}) signal(signum, SIG_DFL);
        auto watch = maintain::watch_process(option.watch, caller.uid);
        maintain::detach(caller, option, std::move(watch));
        std::cout << std::format("FILE:{}/{}\n", caller.home, CACHE_NAME);
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "craft-maintain: " << error.what() << '\n';
        return 1;
    }
}
#endif

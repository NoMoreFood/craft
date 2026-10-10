// CRAFT entry point; certificate, network and Kerberos processing stays in the worker.
#include "common.hpp"
using namespace craft;

int main(int argc, char **)
{
    try
    {
        // Validate real credentials and reset inherited process state.
        const uid_t uid = getuid();
        const gid_t gid = getgid();
        need(argc == 1, "usage: craft (no arguments)");
        need(uid != 0 && (geteuid() == uid || geteuid() == 0), "run directly as a non-root user");
        need(getegid() == gid, "launcher must not be setgid");
        sysneed(clearenv() == 0, "clearenv");
        no_core();
        sigset_t empty;
        sigemptyset(&empty);
        sysneed(sigprocmask(SIG_SETMASK, &empty, nullptr) == 0, "reset signal mask");
        for (const int signum : {SIGPIPE, SIGCHLD, SIGALRM})
            signal(signum, SIG_DFL);
        alarm(120);

        ensure_standard_streams();
        close_from(3);
        sysneed(chdir("/") == 0, "chdir /");

        // Resolve the real UID and retain only validated worker inputs.
        const Account caller = lookup_uid(uid);
        need(simple_name(caller.name), "invalid calling account");
        const int count = getgroups(0, nullptr);
        sysneed(count >= 0, "getgroups");
        std::vector<gid_t> groups(static_cast<size_t>(count));
        if (count) sysneed(getgroups(count, groups.data()) == count, "getgroups");
        const Fd binary = root_open(WORKER, Trusted::Worker);
        const auto uidarg = std::to_string(uid);
        const pid_t launcher = getpid();

        // Run the fixed worker as `account` and publish the cache it returns. In home mode the worker first
        // reports whether the caller supplied a certificate pair; false means the fallback is needed.
        const auto run_worker = [&](const Account &account, bool home)
        {
            Pipe channel = make_pipe();
            Child worker(fork_child(
                [&]() -> int
                {
                    // Redirect the standard streams before relinquishing elevated credentials.
                    {
                        const Fd null(open("/dev/null", O_RDONLY));
                        sysneed(null.get() >= 0 && dup2(null.get(), STDIN_FILENO) == STDIN_FILENO &&
                                    dup2(channel.writer.get(), STDOUT_FILENO) == STDOUT_FILENO,
                                "worker standard streams");
                    }
                    keep_only({binary.get()});
                    if (geteuid() != 0) sysneed(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
                    else if (home) drop(account.uid, gid, groups);
                    else drop(account.uid, account.gid);
                    sysneed(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0, "worker parent-death signal");
                    need(getppid() == launcher, "launcher disappeared");

                    // Execute the verified descriptor with an empty environment; the worker sets its own.
                    const char *args[] = {WORKER,
                                          home ? "--home" : uidarg.c_str(),
                                          home ? uidarg.c_str() : caller.name.c_str(),
                                          home ? caller.name.c_str() : nullptr,
                                          nullptr};
                    char *environment[] = {nullptr};
                    fexecve(3, const_cast<char **>(args), environment);
                    sysfail("exec fixed worker");
                }));
            channel.writer = Fd();
            const auto finish = [&]
            {
                need(worker.wait(), "credential acquisition failed; existing cache was not replaced");
            };

            // Read only the source-selection byte while elevated; credentials require a permanent drop.
            if (home)
            {
                unsigned char selected{};
                ssize_t length;
                do
                    length = read(channel.reader.get(), &selected, 1);
                while (length < 0 && errno == EINTR);
                need(length == 1 && selected <= 1,
                     "user certificate selection failed; existing cache was not replaced");
                if (!selected)
                {
                    finish();
                    return false;
                }
            }
            if (geteuid() == 0) drop(uid, gid, groups);
            auto cache = read_all(channel.reader.get());
            ScopeExit erase([&]() noexcept { wipe(cache); });
            channel.reader = Fd();
            finish();

            // Validate the ticket cache header and publish atomically under the cache lock.
            need(cache.size() > 4 && cache[0] == 5 && cache[1] == 4,
                 "worker returned no valid FILE-cache header");
            const Fd directory = caller_home(caller), lock = cache_lock(directory.get(), CACHE_LOCK);
            publish_cache(directory.get(), cache);
            write_all(STDOUT_FILENO, byte_view(std::format("FILE:{}/{}\n", caller.home, CACHE_NAME)));
            return true;
        };

        // Prefer home credentials entirely under the caller; only the fallback needs the service account.
        if (run_worker(caller, true)) return 0;
        need(geteuid() == 0,
             "no ~/.config/craft/user.pem/user.key pair; the configured fallback (enrollment or Key Trust) "
             "requires the setuid-root launcher");
        const Account service = service_account();
        need(uid != service.uid, "invalid calling account");
        run_worker(service, false);
        return 0;
    }
    catch (const std::exception &error)
    {
        dprintf(STDERR_FILENO, "craft: %s\n", error.what());
        return 1;
    }
}

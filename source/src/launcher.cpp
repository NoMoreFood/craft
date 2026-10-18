// CRAFT entry point; certificate, network and Kerberos processing stays in the worker.
#include "common.hpp"
using namespace craft;

int main(int argc, char **)
{
    const uid_t uid = getuid();
    try
    {
        // Validate real credentials and reset inherited process state.
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
        alarm(ACQUISITION_SECONDS);

        ensure_standard_streams();
        close_from(3);
        sysneed(chdir("/") == 0, "chdir /");

        // Resolve the real UID and retain only validated worker inputs.
        const Account caller = lookup_uid(uid);
        need(simple_name(caller.name), "invalid calling account");

        // Nothing privileged happens unless the host logging service takes this record.
        audit(LOG_INFO, std::format("request started uid={} user={}", uid, caller.name));
        const int count = getgroups(0, nullptr);
        sysneed(count >= 0, "getgroups");
        std::vector<gid_t> groups(static_cast<size_t>(count));
        if (count) sysneed(getgroups(count, groups.data()) == count, "getgroups");
        const Fd binary = root_open(WORKER, Trusted::Worker);
        const auto uidarg = std::to_string(uid);
        const auto request = random_hex();
        Bytes modes;
        bool may_continue = true;

        // Read policy as the caller, then run each enabled mode under its required identity. Only a complete,
        // validated acquisition permits the parent to drop privilege and receive credential bytes.
        const auto run_worker = [&](const Account &account, std::string_view mode)
        {
            const bool policy = mode == "policy", caller_worker = policy || mode == "home";

            // The worker's input is a pipe that is never written: its closing tells the worker, whatever
            // identity it runs under, that this launcher has gone.
            Pipe channel = make_pipe(), alive = make_pipe();
            Child worker(fork_child(
                [&]() -> int
                {
                    // Redirect the standard streams before relinquishing elevated credentials.
                    sysneed(dup2(alive.reader.get(), STDIN_FILENO) == STDIN_FILENO &&
                                dup2(channel.writer.get(), STDOUT_FILENO) == STDOUT_FILENO,
                            "worker standard streams");
                    keep_only({binary.get()});
                    if (geteuid() != 0) sysneed(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
                    else if (caller_worker) drop(account.uid, gid, groups);
                    else drop(account.uid, account.gid);

                    // Execute the verified descriptor with an empty environment; the worker sets its own.
                    const char *args[] = {
                        WORKER, mode.data(), uidarg.c_str(), caller.name.c_str(), request.c_str(), nullptr};
                    char *environment[] = {nullptr};
                    fexecve(3, const_cast<char **>(args), environment);
                    sysfail("exec fixed worker");
                }));
            channel.writer = Fd();
            alive.reader = Fd();
            const auto finish = [&]
            {
                need(worker.wait(), "credential acquisition failed; existing cache was not replaced");
            };

            if (policy)
            {
                modes = read_all(channel.reader.get(), MODE_NAMES.size());
                finish();
                return false;
            }

            // A reported acquisition failure allows the next mode. A crash, failed cleanup or broken
            // protocol stops the request because successful cleanup and credential validation are unknown.
            may_continue = false;
            unsigned char ready{};
            const auto length = retry([&] { return read(channel.reader.get(), &ready, 1); });
            need(length == 1 && ready <= 2, "worker interrupted; existing cache was not replaced");
            if (ready != 1)
            {
                need(worker.wait(1), "worker interrupted or returned an inconsistent acquisition result");
                need(ready == 0, "credential cleanup failed; existing cache was not replaced");
                may_continue = true;
                return false;
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
            audit(LOG_NOTICE,
                  std::format("request finished uid={} user={} outcome=published cache={}/{}",
                              uid,
                              caller.name,
                              caller.home,
                              CACHE_NAME));
            write_all(STDOUT_FILENO, byte_view(std::format("FILE:{}/{}\n", caller.home, CACHE_NAME)));
            return true;
        };

        // The policy response contains only a unique, bounded list; every worker independently verifies
        // that its mode is still enabled in the administrator's configuration.
        run_worker(caller, "policy");
        need(!modes.empty(), "no operating modes enabled");
        std::array<bool, MODE_NAMES.size()> seen{};
        for (const auto mode : modes)
        {
            need(mode < seen.size() && !seen[mode], "invalid operating mode policy");
            seen[mode] = true;
        }
        for (const auto mode : modes)
        {
            const auto name = MODE_NAMES[mode];
            try
            {
                Account account = caller;
                if (name != "home")
                {
                    need(geteuid() == 0, "broker mode requires the setuid-root launcher");
                    account = service_account();
                    need(uid != account.uid, "invalid calling account");
                }
                if (run_worker(account, name)) return 0;
            }
            catch (const std::exception &error)
            {
                if (!may_continue) throw;
                report(error, std::format("mode={} uid={}", name, uid));
            }
            audit(LOG_WARNING, std::format("mode failed uid={} mode={}", uid, name));
        }
        fail("all enabled operating modes failed; existing cache was not replaced");
    }
    catch (const std::exception &error)
    {
        report(error, std::format("request uid={}", uid));
        return 1;
    }
}

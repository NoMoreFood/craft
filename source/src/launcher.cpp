// CRAFT entry point; certificate, network, and Kerberos processing stays in the worker.
#include "common.hpp"
#include <sys/wait.h>
#include <signal.h>
#include <iostream>
using namespace craft;

int main(int argc, char **)
{
    try
    {
        // Validate real credentials and reset inherited process state.
        const uid_t uid = getuid();
        const gid_t gid = getgid();
        need(argc == 1, "usage: craft (no arguments)");
        need(uid != 0 && (geteuid() == uid || geteuid() == 0),
             "run directly as a non-root user");
        need(getegid() == gid, "launcher must not be setgid");
        sysneed(clearenv() == 0, "clearenv");
        no_core();
        sigset_t empty;
        sigemptyset(&empty);
        sysneed(sigprocmask(SIG_SETMASK, &empty, nullptr) == 0, "reset signal mask");
        for (int signum : {SIGPIPE, SIGCHLD, SIGALRM})
            signal(signum, SIG_DFL);
        alarm(120);

        // Ensure standard file descriptors 0-2 are open to prevent descriptor reuse.
        for (int fd = 0; fd < 3; ++fd)
        {
            if (fcntl(fd, F_GETFD) >= 0) continue;
            Fd null(open("/dev/null", fd == 0 ? O_RDONLY : O_WRONLY));
            sysneed(null.get() >= 0, "open /dev/null");
            if (null.get() != fd) sysneed(dup2(null.get(), fd) == fd, "dup standard descriptor");
            else (void)null.release();
        }
        close_from(3);
        sysneed(chdir("/") == 0, "chdir /");

        // Resolve the real UID and retain only validated worker inputs.
        const Account caller = lookup_uid(uid);
        need(simple_name(caller.name), "invalid calling account");
        const int count = getgroups(0, nullptr);
        sysneed(count >= 0, "getgroups");
        std::vector<gid_t> groups(static_cast<size_t>(count));
        if (count) sysneed(getgroups(count, groups.data()) == count, "getgroups");
        const Fd binary = root_open(WORKER, false, true);
        const auto uidarg = std::to_string(uid);

        const auto run_worker = [&](const Account &account, bool home)
        {
            // Open a private channel and execute the trusted worker in the selected account.
            std::array<int, 2> descriptors{};
            sysneed(pipe2(descriptors.data(), O_CLOEXEC) == 0, "worker pipe");
            Fd reader(descriptors[0]), writer(descriptors[1]);
            const pid_t parent = getpid(), child = fork();
            sysneed(child >= 0, "fork");
            if (child == 0)
            {
                try
                {
                    // Redirect standard I/O streams before relinquishing elevated credentials.
                    sysneed(dup2(writer.get(), STDOUT_FILENO) == STDOUT_FILENO, "worker stdout");
                    const Fd null(open("/dev/null", O_RDONLY));
                    sysneed(null.get() >= 0, "worker stdin");
                    sysneed(dup2(null.get(), STDIN_FILENO) == STDIN_FILENO, "worker stdin dup");
                    if (binary.get() != 3) sysneed(dup3(binary.get(), 3, O_CLOEXEC) == 3, "worker executable fd");
                    close_from(4);
                    if (geteuid() == 0)
                        drop(account.uid, home ? gid : account.gid,
                             home ? std::span<const gid_t>(groups) : std::span<const gid_t>{});
                    else
                        sysneed(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "no_new_privs");
                    sysneed(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0, "worker parent-death signal");
                    need(getppid() == parent, "launcher disappeared");

                    // Execute worker binary using verified descriptor with minimal sanitized environment.
                    auto args = std::to_array<char *>({const_cast<char *>(WORKER),
                                                       const_cast<char *>(home ? "--home" : uidarg.c_str()),
                                                       const_cast<char *>(home ? uidarg.c_str() :
                                                                                caller.name.c_str()),
                                                       home ? const_cast<char *>(caller.name.c_str()) : nullptr,
                                                       nullptr});
                    char path[] = "PATH=/usr/bin:/bin", lang[] = "LANG=C", homevar[] = "HOME=/nonexistent";
                    char krb[] = "KRB5_CONFIG=/etc/craft/krb5.conf";
                    auto env = std::to_array<char *>({path, lang, homevar, krb, nullptr});
                    fexecve(3, args.data(), env.data());
                    fail("exec fixed worker failed");
                }
                catch (const std::exception &error)
                {
                    dprintf(STDERR_FILENO, "craft: %s\n", error.what());
                    _exit(1);
                }
            }

            writer = Fd();
            ScopeExit reap([&]() noexcept
            {
                kill(child, SIGKILL);
                waitpid_retry(child, nullptr);
            });
            const auto wait_worker = [&]
            {
                int status{};
                const pid_t waited = waitpid_retry(child, &status, 0);
                sysneed(waited == child, "waitpid");
                reap.release();
                need(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                     "credential acquisition failed; existing cache was not replaced");
            };

            // Read only the source-selection byte while elevated; credentials require a permanent drop.
            if (home)
            {
                unsigned char selected{};
                ssize_t length;
                do
                {
                    length = read(reader.get(), &selected, 1);
                } while (length < 0 && errno == EINTR);
                need(length == 1 && selected <= 1,
                     "user certificate selection failed; existing cache was not replaced");
                if (!selected)
                {
                    wait_worker();
                    return false;
                }
            }
            if (geteuid() == 0) drop(uid, gid, groups);
            auto cache = read_all(reader.get());
            ScopeExit erase([&]() noexcept { wipe(cache); });
            reader = Fd();
            wait_worker();

            // Validate ticket cache format and publish atomically to the caller's home.
            need(cache.size() > 4 && cache[0] == 5 && cache[1] == 4,
                 "worker returned no valid FILE-cache header");
            const Fd directory = caller_home(caller), lock = cache_lock(directory.get(), CACHE_LOCK);
            publish_cache(caller, cache);
            std::cout << std::format("FILE:{}/{}\n", caller.home, CACHE_NAME);
            return true;
        };

        // Prefer home credentials entirely under the caller; enrollment alone needs the service account.
        if (run_worker(caller, true)) return 0;
        need(geteuid() == 0,
             "no ~/.config/craft/user.pem/user.key pair; enrollment requires the setuid-root launcher");
        const Account service = service_account();
        need(uid != service.uid, "invalid calling account");
        run_worker(service, false);
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "craft: " << error.what() << '\n';
        return 1;
    }
}

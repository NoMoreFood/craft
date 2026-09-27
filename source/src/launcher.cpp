// CRAFT setuid entry point; certificate, network, and Kerberos processing stays in the worker.
#include "common.hpp"
#include <sys/wait.h>
#include <signal.h>
#include <iostream>
#include <regex>
using namespace craft;

// Publish a private cache atomically only after dropping to the caller.
static void publish(const Account &caller, ByteView cache)
{
    // Verify caller home directory format and path characters.
    const static std::regex home_re(R"(^/(?:[^/\x00-\x1f\x7f]+/)*[^/\x00-\x1f\x7f]+$)");
    need(std::regex_match(caller.home, home_re), "invalid home directory");

    // Verify caller home directory ownership and restrictive file permissions.
    const Fd home(open(caller.home.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    sysneed(home.get() >= 0, "open caller home after privilege drop");
    struct stat st{};
    sysneed(fstat(home.get(), &st) == 0, "stat home");
    need(st.st_uid == caller.uid && !(st.st_mode & 0022),
         "home must belong to caller and not be group/world-writable");

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

int main(int argc, char **)
{
    try
    {
        // Validate real credentials and reset inherited process state.
        const uid_t uid = getuid();
        const gid_t gid = getgid();
        need(argc == 1, "usage: craft (no arguments)");
        need(uid != 0 && geteuid() == 0,
             "run directly as an authorized non-root user; install launcher setuid-root");
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

        // Resolve the real UID, validate caller identity, and retain only validated worker inputs.
        const Account caller = lookup_uid(uid), service = service_account();
        need(uid != 0 && uid != service.uid && simple_name(caller.name), "invalid calling account");
        need(lookup_uid(uid).name == caller.name, "runtime UID/name changed; administrator review required");
        const int count = getgroups(0, nullptr);
        sysneed(count >= 0, "getgroups");
        std::vector<gid_t> groups(static_cast<size_t>(count));
        if (count) sysneed(getgroups(count, groups.data()) == count, "getgroups");

        // Open worker binary securely from trusted path and set up IPC communication pipe.
        Fd binary = root_open(WORKER, false, true);
        std::array<int, 2> pipe{};
        sysneed(pipe2(pipe.data(), O_CLOEXEC) == 0, "pipe2");
        Fd reader(pipe[0]), writer(pipe[1]);
        const auto uidarg = std::to_string(uid);
        const pid_t parent = getpid(), child = fork();
        sysneed(child >= 0, "fork");

        // Execute the opened worker as the dedicated account with a fixed environment.
        if (child == 0)
        {
            try
            {
                // Redirect standard I/O streams and drop privileges to service account.
                sysneed(dup2(writer.get(), STDOUT_FILENO) == STDOUT_FILENO, "worker stdout");
                const Fd null(open("/dev/null", O_RDONLY));
                sysneed(null.get() >= 0, "worker stdin");
                sysneed(dup2(null.get(), STDIN_FILENO) == STDIN_FILENO, "worker stdin dup");
                if (binary.get() != 3) sysneed(dup3(binary.get(), 3, O_CLOEXEC) == 3, "worker executable fd");
                close_from(4);
                drop(service.uid, service.gid);
                sysneed(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0, "worker parent-death signal");
                need(getppid() == parent, "launcher disappeared");

                // Execute worker binary using verified descriptor with minimal sanitized environment.
                auto args = std::to_array<char *>({const_cast<char *>(WORKER),
                                                   const_cast<char *>(uidarg.c_str()),
                                                   const_cast<char *>(caller.name.c_str()),
                                                   nullptr});
                char path[] = "PATH=/usr/bin:/bin", lang[] = "LANG=C", home[] = "HOME=/nonexistent";
                char krb[] = "KRB5_CONFIG=/etc/craft/krb5.conf";
                auto env = std::to_array<char *>({path, lang, home, krb, nullptr});
                fexecve(3, args.data(), env.data());
                fail("exec fixed worker failed");
            }
            catch (const std::exception &error)
            {
                dprintf(STDERR_FILENO, "craft: %s\n", error.what());
                _exit(1);
            }
        }

        // Drop root before reading credentials or opening anything in the caller's home.
        writer = Fd();
        binary = Fd();
        drop(uid, gid, groups);
        auto cache = read_all(reader.get());
        ScopeExit erase([&]() noexcept { wipe(cache); });
        reader = Fd();
        int status{};
        pid_t waited;

        // Wait for child worker to terminate and inspect exit status.
        do
        {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        sysneed(waited == child, "waitpid");
        need(WIFEXITED(status) && WEXITSTATUS(status) == 0,
             "enrollment/PKINIT failed; existing cache was not replaced");

        // Validate ticket cache format and publish to caller's home directory.
        need(cache.size() > 4 && cache[0] == 5 && cache[1] == 4,
             "worker returned no valid FILE-cache header");
        publish(caller, cache);
        std::cout << std::format("FILE:{}/{}\n", caller.home, CACHE_NAME);
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "craft: " << error.what() << '\n';
        return 1;
    }
}

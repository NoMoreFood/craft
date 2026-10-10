// craft-maintain: start detached credential maintenance for a watched job, or report its status.
#include "maintain.hpp"

int main(int argc, char **argv)
{
    using namespace craft;
    try
    {
        ensure_standard_streams();
        const auto option = maintain::options(argc, argv);
        if (option.help)
        {
            write_all(STDOUT_FILENO,
                      byte_view("Usage: craft-maintain --watch-pid PID [--max-duration 21d] [--status]\n"
                                "Start once as the batch user; stdout is the FILE cache name.\n"
                                "--status reads the latest status for that job, including after it ends.\n"));
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
            const Fd file = open_private(
                home.get(), maintain::status_name(option.watch).c_str(), O_RDONLY, "maintenance status");
            sysneed(file.get() >= 0, "open maintenance status");
            write_all(STDOUT_FILENO, read_all(file.get(), 8192));
            return 0;
        }
        sigset_t empty;
        sigemptyset(&empty);
        sysneed(sigprocmask(SIG_SETMASK, &empty, nullptr) == 0, "reset maintenance signal mask");
        for (const int signum : {SIGPIPE, SIGCHLD, SIGTERM, SIGINT})
            signal(signum, SIG_DFL);
        maintain::detach(caller, option, maintain::watch_process(option.watch, caller.uid));
        write_all(STDOUT_FILENO, byte_view(std::format("FILE:{}/{}\n", caller.home, CACHE_NAME)));
        return 0;
    }
    catch (const std::exception &error)
    {
        dprintf(STDERR_FILENO, "craft-maintain: %s\n", error.what());
        return 1;
    }
}

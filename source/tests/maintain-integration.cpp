// Exercise the detached executable with synthetic credentials in a disposable Linux container.
#include "../src/common.hpp"
#include "harness.hpp"
#include <poll.h>
#include <chrono>
#include <filesystem>
#include <map>
#include <sstream>

namespace craft::integration
{
using Clock = std::chrono::steady_clock;
using Status = std::map<std::string, std::string>;
std::string maintain, fixtures, home, cache, mode, issuance;

struct Process
{
    pid_t pid = 0;
    Fd output, error;
};

struct Result
{
    int code;
    std::string output, error;
};

void terminate(Process &child) noexcept
{
    if (child.pid <= 0) return;
    kill(-child.pid, SIGKILL);
    kill(child.pid, SIGKILL);
    while (waitpid(child.pid, nullptr, 0) < 0 && errno == EINTR)
    {
    }
    child.pid = 0;
}

Process spawn(std::vector<std::string> arguments, bool closed_streams = false)
{
    // Prepare arguments and independent capture pipes before forking.
    std::vector<char *> argv;
    for (auto &argument : arguments)
        argv.push_back(argument.data());
    argv.push_back(nullptr);
    std::array<int, 2> descriptors{};
    sysneed(pipe2(descriptors.data(), O_CLOEXEC) == 0, "stdout pipe");
    Fd output(descriptors[0]), output_writer(descriptors[1]);
    sysneed(pipe2(descriptors.data(), O_CLOEXEC) == 0, "stderr pipe");
    Fd error(descriptors[0]), error_writer(descriptors[1]);
    const Fd null(open("/dev/null", O_RDWR | O_CLOEXEC));
    sysneed(null.get() >= 0 && fcntl(output.get(), F_SETFL, O_NONBLOCK) == 0 &&
                fcntl(error.get(), F_SETFL, O_NONBLOCK) == 0,
            "prepare child streams");
    Process child;
    child.pid = fork();
    sysneed(child.pid >= 0, "fork test process");
    if (child.pid == 0)
    {
        if (setpgid(0, 0) != 0 || dup2(null.get(), 0) < 0 || dup2(output_writer.get(), 1) < 0 ||
            dup2(error_writer.get(), 2) < 0)
            _exit(127);
        if (closed_streams)
        {
            close(0);
            close(2);
        }
        execv(argv[0], argv.data());
        _exit(127);
    }
    ScopeExit cleanup([&]() noexcept { terminate(child); });
    if (setpgid(child.pid, child.pid) != 0) need(errno == EACCES || errno == ESRCH, "child process group");
    child.output = std::move(output);
    child.error = std::move(error);
    cleanup.release();
    return child;
}

Result collect(Process &child, uint32_t timeout = 10)
{
    ScopeExit cleanup([&]() noexcept { terminate(child); });
    Result result{};
    int status = 0;
    bool running = true;
    const auto deadline = Clock::now() + std::chrono::seconds(timeout);

    // Drain both streams until EOF and exit; retained background pipes must still hit the deadline. The
    // command is this process's child, so its exit is observed without a pidfd.
    while (running || child.output.get() >= 0 || child.error.get() >= 0)
    {
        need(Clock::now() < deadline, "test command timed out or retained an output pipe");
        if (running)
        {
            const pid_t waited = waitpid_retry(child.pid, &status, WNOHANG);
            sysneed(waited >= 0, "reap test process");
            running = waited == 0;
        }
        std::array<pollfd, 2> descriptors{{{child.output.get(), POLLIN, 0}, {child.error.get(), POLLIN, 0}}};
        const auto count = poll(descriptors.data(), descriptors.size(), 20);
        if (count < 0 && errno == EINTR) continue;
        sysneed(count >= 0, "poll test process");
        for (int i = 0; i < 2; ++i)
        {
            if (!descriptors[i].revents) continue;
            auto &file = i == 0 ? child.output : child.error;
            auto &text = i == 0 ? result.output : result.error;
            std::array<char, 4096> buffer{};
            for (;;)
            {
                const auto length = read(file.get(), buffer.data(), buffer.size());
                if (length < 0 && errno == EINTR) continue;
                if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                sysneed(length >= 0, "read test process stream");
                if (!length)
                {
                    file = Fd();
                    break;
                }
                need(static_cast<size_t>(length) <= MAX_BLOB - text.size(),
                     "test process output exceeds limit");
                text.append(buffer.data(), static_cast<size_t>(length));
            }
        }
    }
    child.pid = 0;
    result.code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    cleanup.release();
    return result;
}

Result run(std::vector<std::string> arguments, bool closed_streams = false)
{
    auto child = spawn(std::move(arguments), closed_streams);
    return collect(child);
}

Bytes read_file(const std::string &path, size_t maximum = MAX_BLOB)
{
    const Fd file(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    sysneed(file.get() >= 0, "open fixture file " + path);
    return read_all(file.get(), maximum);
}

Status status(pid_t pid)
{
    const auto path = std::format("{}.maintain.{}.status", cache, pid);
    const Fd file(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    sysneed(file.get() >= 0 || errno == ENOENT, "open test status");
    if (file.get() < 0) return {};
    const auto bytes = read_all(file.get(), 8192);
    std::istringstream input(std::string(bytes.begin(), bytes.end()));
    Status result;
    std::string line;
    while (std::getline(input, line))
    {
        const auto equal = line.find('=');
        need(equal != line.npos, "malformed test status");
        result.emplace(line.substr(0, equal), line.substr(equal + 1));
    }
    return result;
}

Status wait_status(pid_t pid, std::initializer_list<std::string_view> states, uint32_t timeout = 5)
{
    const auto deadline = Clock::now() + std::chrono::seconds(timeout);
    while (Clock::now() < deadline)
    {
        auto report = status(pid);
        const auto found = report.find("state");
        if (found != report.end() && std::ranges::find(states, found->second) != states.end()) return report;
        poll(nullptr, 0, 20);
    }
    fail(std::format("job {} did not reach its expected maintenance state", pid));
}

void with_jobs(size_t count, auto action)
{
    std::vector<Process> jobs;
    jobs.reserve(count);
    ScopeExit cleanup(
        [&]() noexcept
        {
            for (auto &job : jobs)
                terminate(job);
        });
    for (size_t i = 0; i < count; ++i)
        jobs.push_back(spawn({"/usr/bin/sleep", "60"}));
    action(jobs);

    // Reap watched processes before checking that their detached maintainers stopped.
    for (auto &job : jobs)
    {
        const auto pid = job.pid;
        terminate(job);
        if (!status(pid).empty()) wait_status(pid, {"stopped", "failed"});
    }
}

void reset(std::string_view kind = {}, std::string_view issuer = "healthy")
{
    for (const auto &path : {cache, issuance, cache + ".maintain.retry"})
        sysneed(unlink(path.c_str()) == 0 || errno == ENOENT, "reset test fixture");
    const Fd file(open(mode.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    sysneed(file.get() >= 0 && fchmod(file.get(), 0600) == 0, "write issuer mode");
    write_all(file.get(), byte_view(issuer));
    if (kind.empty()) return;
    const auto result = run({fixtures, "--maintain-fixture", std::string(kind)});
    need(result.code == 0, "create cache fixture: " + result.error);
}

size_t issued()
{
    const Fd file(open(issuance.c_str(), O_RDONLY | O_CLOEXEC));
    sysneed(file.get() >= 0 || errno == ENOENT, "read issuance count");
    if (file.get() < 0) return 0;
    return static_cast<size_t>(std::ranges::count(read_all(file.get()), '\n'));
}

std::vector<std::string> command(pid_t pid, std::string duration = "8s")
{
    return {maintain, "--watch-pid", std::to_string(pid), "--max-duration", std::move(duration)};
}

void test(std::string_view name, auto action)
{
    testing::test(name, action, true);
}

void checks()
{
    test("maintenance updates handle enrollment outages and shortened renewal grants",
         []
         {
             const auto result = run({fixtures, "--maintain-update-tests"});
             need(result.code == 0, result.output + result.error);
         });
    test("healthy startup returns only the cache name and stops with its job",
         []
         {
             reset("healthy");
             const auto before = read_file(cache);
             pid_t watched = 0;
             with_jobs(
                 1,
                 [&](const auto &jobs)
                 {
                     watched = jobs.front().pid;
                     const auto begin = Clock::now();
                     const auto result = run(command(watched));
                     need(result.code == 0, result.error);
                     need(Clock::now() - begin < std::chrono::seconds(5),
                          "startup retained the captured stdout pipe");
                     need(result.output == "FILE:" + cache + "\n" && status(watched).at("state") == "ready",
                          "startup did not return a usable cache and ready status");
                     need(read_file(cache) == before && issued() == 0, "healthy startup changed credentials");
                     struct stat info
                     {
                     };
                     need(stat(cache.c_str(), &info) == 0 && (info.st_mode & 0777) == 0600,
                          "cache is not private");
                     const auto report = run({maintain, "--status", "--watch-pid", std::to_string(watched)});
                     need(report.code == 0 && report.output.find("state=ready\n") != report.output.npos,
                          "status command did not report ready");
                 });
             need(status(watched).at("state") == "stopped", "job exit did not stop maintenance");
         });
    test("startup retains lifecycle descriptors with closed stdin and stderr",
         []
         {
             reset("healthy");
             with_jobs(1,
                       [](const auto &jobs)
                       {
                           const auto pid = jobs.front().pid;
                           const auto result = run(command(pid), true);
                           need(result.code == 0 && result.output == "FILE:" + cache + "\n",
                                "closed-stream startup failed");
                           need(status(pid).at("state") == "ready" && issued() == 0,
                                "closed-stream startup changed credentials");
                       });
         });
    for (const std::string_view kind : {"", "expired", "rollover", "nonrenewable"})
        test(std::format("{} credentials enroll exactly once", kind.empty() ? "missing" : kind),
             [&]
             {
                 reset(kind);
                 with_jobs(1,
                           [](const auto &jobs)
                           {
                               const auto pid = jobs.front().pid;
                               const auto result = run(command(pid));
                               need(result.code == 0, result.error);
                               const auto report = status(pid);
                               need(report.at("state") == "ready" && issued() == 1,
                                    "fresh credentials were not issued once");
                               need(std::stoll(report.at("tgt_expires")) > time(nullptr) + 35000,
                                    "fresh TGT expires too soon");
                           });
             });
    test("denied enrollment preserves the previous cache and fails startup",
         []
         {
             reset("expired", "deny");
             const auto before = read_file(cache);
             with_jobs(1,
                       [&](const auto &jobs)
                       {
                           const auto pid = jobs.front().pid;
                           const auto result = run(command(pid));
                           need(result.code != 0 && result.output.empty(),
                                "denied enrollment reported startup success");
                           const auto report = wait_status(pid, {"failed"});
                           need(report.at("last_error").find("synthetic enrollment denied") !=
                                    std::string::npos,
                                "denied enrollment lost its diagnostic");
                           need(read_file(cache) == before && issued() == 1,
                                "denied enrollment changed the old cache");
                       });
         });
    test("KDC outage retries renewal without certificate issuance",
         []
         {
             reset("renew");
             const auto before = read_file(cache);
             with_jobs(1,
                       [&](const auto &jobs)
                       {
                           const auto pid = jobs.front().pid;
                           const auto result = run(command(pid));
                           need(result.code == 0, result.error);
                           const auto report = status(pid);
                           need(report.at("state") == "retrying" &&
                                    report.at("last_error").find("renew user TGT") != std::string::npos,
                                "renewal outage did not report retrying");
                           need(issued() == 0 && read_file(cache) == before,
                                "renewal failure caused enrollment or cache loss");
                       });
         });
    for (const bool denied : {false, true})
        test(denied ? "concurrent rollover failures share enrollment backoff and retain a usable cache"
                    : "concurrent job startup shares one enrollment",
             [&]
             {
                 reset(denied ? "rollover" : "", denied ? "deny" : "healthy");
                 const auto before = denied ? read_file(cache) : Bytes{};
                 with_jobs(5,
                           [&](const auto &jobs)
                           {
                               std::vector<Process> starts;
                               starts.reserve(jobs.size());
                               ScopeExit cleanup(
                                   [&]() noexcept
                                   {
                                       for (auto &child : starts)
                                           terminate(child);
                                   });
                               for (const auto &job : jobs)
                                   starts.push_back(spawn(command(job.pid)));
                               for (auto &child : starts)
                               {
                                   const auto result = collect(child);
                                   need(result.code == 0, result.error);
                               }
                               need(issued() == 1, "concurrent startup did not share one enrollment attempt");
                               if (denied)
                                   need(read_file(cache) == before,
                                        "failed rollover changed the usable cache");
                               for (const auto &job : jobs)
                               {
                                   const auto report = status(job.pid);
                                   need(report.at("state") == (denied ? "retrying" : "ready"),
                                        "unexpected concurrent status");
                                   if (denied)
                                       need(std::stoll(report.at("next_check")) >= time(nullptr) + 50,
                                            "jobs did not share enrollment failure backoff");
                               }
                           });
             });
    test("maximum duration stops maintenance while the job remains alive",
         []
         {
             reset("healthy");
             with_jobs(1,
                       [](const auto &jobs)
                       {
                           const auto &job = jobs.front();
                           const auto result = run(command(job.pid, "1s"));
                           need(result.code == 0, result.error);
                           wait_status(job.pid, {"stopped"}, 3);
                           need(waitpid_retry(job.pid, nullptr, WNOHANG) == 0 && issued() == 0,
                                "duration cutoff ended the batch job");
                       });
         });
    test("deadline cancels an in-flight issuer and closes the startup pipe",
         []
         {
             reset({}, "delay");
             with_jobs(1,
                       [](const auto &jobs)
                       {
                           const auto pid = jobs.front().pid;
                           const auto begin = Clock::now();
                           const auto result = run(command(pid, "1s"));
                           need(result.code != 0 && Clock::now() - begin < std::chrono::seconds(5),
                                "startup did not cancel the slow issuer");
                           wait_status(pid, {"failed"});
                           struct stat info
                           {
                           };
                           need(issued() == 1 && lstat(cache.c_str(), &info) < 0 && errno == ENOENT,
                                "cancelled operation published credentials");
                       });
         });
    for (const std::string_view kind : {"symlink", "permissions", "malformed"})
        test(std::format("unsafe {} cache fails without enrollment or replacement", kind),
             [&]
             {
                 reset("healthy");
                 if (kind == "symlink")
                     sysneed(unlink(cache.c_str()) == 0 && symlink(mode.c_str(), cache.c_str()) == 0,
                             "cache symlink");
                 else if (kind == "permissions")
                     sysneed(chmod(cache.c_str(), 0644) == 0, "cache permissions");
                 else
                 {
                     const Fd file(open(cache.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC));
                     sysneed(file.get() >= 0, "open malformed cache");
                     write_all(file.get(), byte_view("INVALID CACHE"));
                 }
                 const auto before = read_file(cache);
                 with_jobs(1,
                           [&](const auto &jobs)
                           {
                               const auto pid = jobs.front().pid;
                               const auto result = run(command(pid));
                               need(result.code != 0 && result.output.empty(),
                                    "unsafe cache reported startup success");
                               wait_status(pid, {"failed"});
                               need(read_file(cache) == before && issued() == 0,
                                    "unsafe cache was replaced or caused enrollment");
                           });
             });
}
} // namespace craft::integration

int main(int argc, char **argv)
{
    using namespace craft;
    using namespace craft::integration;
    try
    {
        need(argc == 3, "usage: craft-maintain-tests CRAFT_MAINTAIN CRAFT_TESTS");

        // Refuse production accounts and verify the installed issuer is the synthetic fixture executable.
        const auto caller = lookup_uid(getuid());
        need(caller.name == "craft-maintain-test" && caller.home == "/home/craft-maintain-test",
             "run only as the isolated craft-maintain-test account in a disposable Linux container");
        maintain = std::filesystem::canonical(argv[1]).string();
        fixtures = std::filesystem::canonical(argv[2]).string();
        need(read_file(LAUNCHER, 32 * MAX_BLOB) == read_file(fixtures, 32 * MAX_BLOB),
             "the isolated issuer must be a copy of craft-tests, never a real CRAFT installation");
        home = caller.home;
        cache = home + "/" + CACHE_NAME;
        mode = home + "/.maintain-test-mode";
        issuance = home + "/.maintain-test-issuance";
        checks();
        return testing::finish("Credentials and issuer are synthetic.");
    }
    catch (const std::exception &error)
    {
        std::cerr << "craft-maintain-tests: " << error.what() << '\n';
        return 1;
    }
}

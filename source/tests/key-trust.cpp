// Exercise real cleanup processes with a shared directory fixture; LDAP never leaves this process tree.
#include "../src/directory.hpp"
#include "harness.hpp"
#include <sys/mman.h>
using namespace craft;

inline constexpr char OBJECT_REF[] = "<GUID=00112233445566778899aabbccddeeff>";
inline constexpr char KEY_VALUE[] = "B:8:01020304:<GUID=00112233445566778899aabbccddeeff>";

struct DirectoryFixture
{
    int attached = 0, removals = 0, wrong_target = 0, add_result = LDAP_SUCCESS, delete_result = LDAP_SUCCESS;
    int bind_result = LDAP_SUCCESS, lock_retained = 0, add_delay_ms = 0;
    volatile pid_t guardian = 0;
    ino_t lock_inode = 0;
};
static DirectoryFixture *directory_fixture = nullptr;

extern "C" int __wrap_ldap_initialize(LDAP **ld, const char *)
{
    *ld = reinterpret_cast<LDAP *>(directory_fixture);
    directory_fixture->guardian = getpid();
    return LDAP_SUCCESS;
}

extern "C" int __wrap_ldap_set_option(LDAP *, int, const void *)
{
    return LDAP_OPT_SUCCESS;
}

extern "C" int __wrap_ldap_sasl_interactive_bind_s(LDAP *,
                                                   const char *,
                                                   const char *,
                                                   LDAPControl **,
                                                   LDAPControl **,
                                                   unsigned,
                                                   LDAP_SASL_INTERACT_PROC *,
                                                   void *)
{
    return directory_fixture->bind_result;
}

extern "C" int __wrap_ldap_unbind_ext_s(LDAP *, LDAPControl **, LDAPControl **)
{
    return LDAP_SUCCESS;
}

extern "C" int
__wrap_ldap_modify_ext_s(LDAP *, const char *dn, LDAPMod **mods, LDAPControl **, LDAPControl **)
{
    // Model a renamed account whose old DN is gone, and preserve its unrelated key credentials.
    if (std::string_view(dn) != OBJECT_REF ||
        std::string_view(mods[0]->mod_type) != "msDS-KeyCredentialLink" || !mods[0]->mod_values ||
        std::string_view(mods[0]->mod_values[0]) != KEY_VALUE || mods[0]->mod_values[1])
    {
        ++directory_fixture->wrong_target;
        return LDAP_NO_SUCH_OBJECT;
    }
    if (mods[0]->mod_op == LDAP_MOD_ADD)
    {
        if (directory_fixture->add_delay_ms) usleep(directory_fixture->add_delay_ms * 1000);
        if (directory_fixture->add_result == LDAP_SUCCESS || LDAP_API_ERROR(directory_fixture->add_result))
            directory_fixture->attached = 1;
        return directory_fixture->add_result;
    }
    if (mods[0]->mod_op != LDAP_MOD_DELETE)
    {
        ++directory_fixture->wrong_target;
        return LDAP_OTHER;
    }
    struct stat st
    {
    };
    directory_fixture->lock_retained = fstat(5, &st) == 0 && st.st_ino == directory_fixture->lock_inode;
    ++directory_fixture->removals;
    if (directory_fixture->delete_result != LDAP_SUCCESS) return directory_fixture->delete_result;
    if (!directory_fixture->attached) return LDAP_NO_SUCH_ATTRIBUTE;
    directory_fixture->attached = 0;
    return LDAP_SUCCESS;
}

static void aborted_worker(const Config &cfg, int signum, int lock_fd)
{
    std::array<int, 2> ready{};
    sysneed(pipe2(ready.data(), O_CLOEXEC) == 0, "fixture worker pipe");
    Fd reader(ready[0]), writer(ready[1]);
    const pid_t worker = fork();
    sysneed(worker >= 0, "fixture worker fork");
    if (worker == 0)
    {
        try
        {
            signal(SIGALRM, SIG_DFL);
            pid_t guardian = -1;
            Fd trigger = start_key_credential_cleanup(cfg, OBJECT_REF, KEY_VALUE, guardian, lock_fd);
            const unsigned char armed = 1;
            write_all(writer.get(), {&armed, 1});
            writer = Fd();
            alarm(signum == SIGALRM ? 1 : 5);
            for (;;)
                pause();
        }
        catch (...)
        {
            _exit(1);
        }
    }
    writer = Fd();
    ScopeExit reap(
        [&]() noexcept
        {
            kill(worker, SIGKILL);
            (void)waitpid_retry(worker);
        });
    need(read_all(reader.get(), 1) == Bytes{1}, "fixture worker could not publish its key");
    const pid_t guardian = directory_fixture->guardian;
    need(guardian > 0 && guardian != worker, "independent cleanup process missing");

    // The guardian has left the worker's session, so the terminal cannot reach it; signals sent directly,
    // including quit and suspend, must not abort or stall cleanup either.
    need(getsid(guardian) == guardian && getsid(worker) != guardian,
         "cleanup process shares the caller's session");
    for (const int interrupt : {SIGTERM, SIGINT, SIGQUIT, SIGTSTP, SIGHUP, SIGPIPE, SIGALRM, SIGUSR1})
        sysneed(kill(guardian, interrupt) == 0, "signal cleanup process");
    if (signum != SIGALRM) sysneed(kill(worker, signum) == 0, "terminate fixture worker");
    int status{};
    sysneed(waitpid_retry(worker, &status) == worker, "wait for fixture worker");
    reap.release();
    need(WIFSIGNALED(status) && WTERMSIG(status) == signum,
         "worker did not terminate by the intended signal");
    sysneed(waitpid_retry(guardian, &status) == guardian, "wait for orphaned cleanup process");
    need(WIFEXITED(status) && WEXITSTATUS(status) == 0 && !directory_fixture->attached &&
             directory_fixture->removals == 1 && !directory_fixture->wrong_target &&
             directory_fixture->lock_retained,
         "worker termination left a key or lost the issuance lock during cleanup");
}

int main()
{
    sysneed(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0, "adopt orphaned cleanup processes");
    void *memory =
        mmap(nullptr, sizeof(DirectoryFixture), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    sysneed(memory != MAP_FAILED, "shared directory fixture");
    directory_fixture = new (memory) DirectoryFixture;
    ScopeExit unmap([&]() noexcept { (void)munmap(memory, sizeof(DirectoryFixture)); });
    Config cfg;
    cfg.kt_dc_url = "ldap://fixture.invalid";
    const auto test = [&](const char *name, auto &&check)
    {
        *directory_fixture = {};
        testing::test(name, check);
    };

    test("lost add response still removes the committed value by GUID",
         [&]
         {
             directory_fixture->add_result = LDAP_TIMEOUT;
             Fd trigger;
             pid_t guardian = -1;
             int status = -1;
             bool rejected = false;
             try
             {
                 ScopeExit cleanup(
                     [&]() noexcept
                     {
                         trigger = Fd();
                         if (guardian > 0) (void)waitpid_retry(guardian, &status);
                     });
                 trigger = start_key_credential_cleanup(cfg, OBJECT_REF, KEY_VALUE, guardian, -1);
             }
             catch (const std::exception &)
             {
                 rejected = true;
             }
             need(rejected && WIFEXITED(status) && WEXITSTATUS(status) == 1 && !directory_fixture->attached &&
                      directory_fixture->removals == 1 && !directory_fixture->wrong_target,
                  "committed write was not removed after its response was lost");
         });

    test("successful acquisition waits for single-value cleanup",
         [&]
         {
             pid_t guardian = -1;
             Fd trigger = start_key_credential_cleanup(cfg, OBJECT_REF, KEY_VALUE, guardian, -1);
             finish_key_credential_cleanup(trigger, guardian);
             need(guardian == -1 && !directory_fixture->attached && directory_fixture->removals == 1 &&
                      !directory_fixture->wrong_target,
                  "successful acquisition returned before cleanup");
         });

    for (int result : {LDAP_UNAVAILABLE, LDAP_NO_SUCH_OBJECT})
    {
        test(result == LDAP_UNAVAILABLE ? "directory cleanup failure refuses credential release"
                                        : "a missing cleanup target is not reported as success",
             [&]
             {
                 directory_fixture->delete_result = result;
                 pid_t guardian = -1;
                 Fd trigger = start_key_credential_cleanup(cfg, OBJECT_REF, KEY_VALUE, guardian, -1);
                 bool rejected = false;
                 try
                 {
                     finish_key_credential_cleanup(trigger, guardian);
                 }
                 catch (const std::exception &)
                 {
                     rejected = true;
                 }
                 need(rejected && directory_fixture->attached && directory_fixture->removals == 2 &&
                          guardian == -1,
                      "cleanup failure was not retried and refused");
             });
    }

    test("cleanup bind failure prevents publication",
         [&]
         {
             directory_fixture->bind_result = LDAP_UNAVAILABLE;
             pid_t guardian = -1;
             bool rejected = false;
             try
             {
                 Fd trigger = start_key_credential_cleanup(cfg, OBJECT_REF, KEY_VALUE, guardian, -1);
             }
             catch (const std::exception &)
             {
                 rejected = true;
             }
             int status{};
             if (guardian > 0) (void)waitpid_retry(guardian, &status);
             need(rejected && !directory_fixture->attached && directory_fixture->removals == 0,
                  "publication was allowed without armed cleanup");
         });

    test("a rejected add does not report a residual credential",
         [&]
         {
             directory_fixture->add_result = LDAP_INSUFFICIENT_ACCESS;
             pid_t guardian = -1;
             bool rejected = false;
             try
             {
                 Fd trigger = start_key_credential_cleanup(cfg, OBJECT_REF, KEY_VALUE, guardian, -1);
             }
             catch (const std::exception &)
             {
                 rejected = true;
             }
             int status{};
             if (guardian > 0) (void)waitpid_retry(guardian, &status);
             need(rejected && !directory_fixture->attached && directory_fixture->removals == 0,
                  "a directory refusal was mistaken for an uncertain write");
         });

    test("worker death during publication removes the delayed add",
         [&]
         {
             directory_fixture->add_delay_ms = 200;
             const pid_t worker = fork();
             sysneed(worker >= 0, "fixture publication worker");
             if (worker == 0)
             {
                 pid_t guardian = -1;
                 Fd trigger = start_key_credential_cleanup(cfg, OBJECT_REF, KEY_VALUE, guardian, -1);
                 _exit(1);
             }
             ScopeExit reap(
                 [&]() noexcept
                 {
                     kill(worker, SIGKILL);
                     (void)waitpid_retry(worker);
                 });
             for (int i = 0; i < 100 && !directory_fixture->guardian; ++i)
                 usleep(10000);
             const pid_t guardian = directory_fixture->guardian;
             need(guardian > 0 && guardian != worker, "publication process did not start");
             sysneed(kill(worker, SIGKILL) == 0, "kill worker during LDAP add");
             int status{};
             sysneed(waitpid_retry(worker, &status) == worker, "wait for publication worker");
             reap.release();
             sysneed(waitpid_retry(guardian, &status) == guardian, "wait for delayed publication cleanup");
             need(!directory_fixture->attached && directory_fixture->removals == 1,
                  "LDAP add completed after cleanup and left a key");
         });

    for (int signum : {SIGKILL, SIGALRM})
    {
        test(signum == SIGKILL ? "cleanup survives worker SIGKILL and terminal signals"
                               : "cleanup survives worker timeout",
             [&]
             {
                 char filename[] = "/tmp/craft-key-lock-XXXXXX";
                 Fd lock(mkstemp(filename));
                 sysneed(lock.get() >= 0 && flock(lock.get(), LOCK_EX | LOCK_NB) == 0,
                         "fixture issuance lock");
                 ScopeExit remove([&]() noexcept { unlink(filename); });
                 struct stat st
                 {
                 };
                 sysneed(fstat(lock.get(), &st) == 0, "fixture lock inode");
                 directory_fixture->lock_inode = st.st_ino;
                 aborted_worker(cfg, signum, lock.get());
             });
    }
    return testing::finish("No live directory operations performed.");
}

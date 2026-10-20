// Coverage-guided fuzzing of every parser that takes bytes someone else controls: configuration, state
// records, certificates and their hand-decoded extensions, the CES response, Kerberos tickets, /proc text and
// command-line options. Built only with -DCRAFT_FUZZ=ON under Clang; see TESTING.md. The first input byte
// selects the parser. An exception is the expected rejection, so only a crash or a sanitizer report is a
// finding.
#include "../src/directory.hpp"
#include "../src/enroll.hpp"
#include "../src/maintain.hpp"
#include "../src/pkinit.hpp"
#include "fuzz-targets.hpp"
#include <sys/mman.h>

namespace
{
using namespace craft;

// One signed certificate, key and scratch directory serve every run.
struct Fixture
{
    Key key = generate_key(2048);
    Cert certificate;
    KrbContext context;
    Config cfg;
    Mapping mapping{.name = "alice", .upn = "alice@domain.local"};
    Fd proc;

    Fixture()
    {
        const Name name = common_name_only("FUZZ ONLY");
        certificate = new_certificate(name.get(), name.get(), key.get(), 600);
        for (const auto &extension : {conf_extension(NID_basic_constraints, "critical,CA:FALSE"),
                                      conf_extension(NID_key_usage, "critical,digitalSignature"),
                                      logon_eku_extension()})
            sslneed(X509_add_ext(certificate.get(), extension.get(), -1) == 1, "fixture extension");
        sslneed(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0, "fixture signature");
        krb_check(nullptr, krb5_init_secure_context(out(context)), "fixture Kerberos context");
        cfg.domain = "domain.local";
        cfg.template_oid = "1.3.6.1.4.1.311.21.8.999.1";
        char directory[] = "/tmp/craft-fuzz-XXXXXX";
        need(mkdtemp(directory) != nullptr, "fixture directory");
        proc = Fd(open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        sysneed(proc.get() >= 0, "open fixture directory");
    }
};

// Run the certificate checks one by one: each must reject or accept by itself, whatever the others did.
void inspect(X509 *certificate, const Fixture &fixture)
{
    const auto attempt = [](std::invocable auto &&check)
    {
        try
        {
            check();
        }
        catch (const std::exception &)
        {
        }
    };
    attempt([&] { (void)certificate_upn(certificate); });
    attempt([&] { (void)certificate_template(certificate); });
    for (const auto source :
         {CertificateSource::Enrollment, CertificateSource::Home, CertificateSource::KeyTrust})
        attempt(
            [&]
            {
                Config cfg = fixture.cfg;
                cfg.source = source;
                (void)validate_leaf(certificate, fixture.key.get(), fixture.mapping, cfg);
            });
}

Fd file_holding(ByteView input)
{
    Fd file(memfd_create("craft-fuzz", MFD_CLOEXEC));
    sysneed(file.get() >= 0, "memfd_create");
    write_all(file.get(), input);
    return file;
}

void run(testing::FuzzTarget target, ByteView input, Fixture &fixture)
{
    using testing::FuzzTarget;
    const std::string text(input.begin(), input.end());
    switch (target)
    {
    case FuzzTarget::Config:
        (void)parse_config(text);
        break;
    case FuzzTarget::HomeConfig:
        (void)parse_config(text, CertificateSource::Home);
        break;
    case FuzzTarget::Response:
        inspect(parse_response(text, fixture.key.get()).get(), fixture);
        break;
    case FuzzTarget::Base64:
        (void)unbase64(text);
        break;
    case FuzzTarget::Extension:
    {
        // The two extensions CRAFT decodes itself, inside an otherwise valid certificate.
        const Cert certificate(X509_dup(fixture.certificate.get()));
        sslneed(certificate != nullptr, "copy fixture certificate");
        for (const char *oid : {SAN_OID, TEMPLATE_OID})
            sslneed(X509_add_ext(certificate.get(), raw_extension(oid, input).get(), -1) == 1,
                    "fixture extension");
        inspect(certificate.get(), fixture);
        break;
    }
    case FuzzTarget::Pem:
        if (const Cert certificate = read_cert(input)) inspect(certificate.get(), fixture);
        (void)read_key(input);
        break;
    case FuzzTarget::Der:
    {
        const unsigned char *cursor = input.data();
        if (const Cert certificate{d2i_X509(nullptr, &cursor, static_cast<long>(input.size()))})
            inspect(certificate.get(), fixture);
        break;
    }
    case FuzzTarget::Ticket:
    {
        std::string encoded = text;
        const krb5_data data{
            .magic = 0, .length = static_cast<unsigned>(encoded.size()), .data = encoded.data()};
        (void)ticket_enctype(fixture.context.get(), data);
        break;
    }
    case FuzzTarget::Options:
    {
        // Arguments are separated by NUL, as the kernel delivers them.
        std::vector<std::string> arguments{"craft-maintain"};
        for (const auto part : text | std::views::split('\0'))
            if (arguments.size() < 16) arguments.emplace_back(part.begin(), part.end());
        std::vector<char *> argv;
        for (auto &argument : arguments)
            argv.push_back(argument.data());
        (void)maintain::options(static_cast<int>(argv.size()), argv.data());
        break;
    }
    case FuzzTarget::Record:
    {
        // A state file as an earlier run, or anyone who can write it, left it.
        const Fd file = file_holding(input);
        maintain::Result result;
        maintain::claim_enrollment(file.get(), 900, result);
        break;
    }
    case FuzzTarget::Text:
    {
        (void)simple_name(text);
        (void)plain_url(text, "https://");
        (void)sanitize_ascii(text);
        (void)domain_to_dn(text);
        Config cfg = fixture.cfg;
        cfg.certificate_cn = text;
        (void)common_name(cfg, "alice", "alice@domain.local");
        break;
    }
    case FuzzTarget::ProcStat:
    {
        // /proc/<pid>/stat carries the watched job's own, arbitrary, command name.
        const Fd file(openat(fixture.proc.get(), "stat", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
        sysneed(file.get() >= 0, "write fixture stat");
        write_all(file.get(), input);
        (void)maintain::exited(maintain::Watch{Fd(dup(fixture.proc.get())), false});
        break;
    }
    case FuzzTarget::Count:
        break;
    }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static Fixture fixture;
    if (size == 0) return 0;
    try
    {
        const auto target =
            static_cast<testing::FuzzTarget>(data[0] % static_cast<int>(testing::FuzzTarget::Count));
        run(target, {data + 1, size - 1}, fixture);
    }
    catch (const std::exception &)
    {
    }
    ERR_clear_error();
    return 0;
}

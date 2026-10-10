#pragma once

// Strict parsing of the administrator's configuration, independent of privileged file access.
#include "common.hpp"
#include <map>
#include <ranges>
#include <regex>
#include <sstream>

namespace craft
{
inline std::string path(std::string_view name)
{
    return std::format("{}/{}", CONFIG_DIR, name);
}

enum class CertificateSource
{
    Enrollment,
    Home,
    KeyTrust
};

struct Config
{
    std::string domain, realm, netbios, template_oid, ces_url, ces_auth, service_principal;
    std::string certificate_cn = "{user}";
    std::string gc_url, gc_base_dn, kt_dc_url;
    uint32_t tgt = 36000, renew = 604800, cert_remaining = 36000, cert_total = 36000, interval = 60;
    bool require_full_tgt_lifetime = true;
    CertificateSource source = CertificateSource::Enrollment;
};

inline std::string domain_to_dn(std::string_view domain)
{
    std::string dn;
    for (const auto part : domain | std::views::split('.'))
    {
        if (!dn.empty()) dn += ",";
        dn += "DC=";
        dn.append(part.begin(), part.end());
    }
    return dn;
}

// Accept scheme://host[:port][/path] in printable ASCII, without credentials, query, fragment or backslashes.
inline bool plain_url(std::string_view url, std::string_view scheme)
{
    if (!url.starts_with(scheme) || url.size() > 2048) return false;
    const auto rest = url.substr(scheme.size());
    return !rest.empty() && rest.front() != '/' && rest.front() != ':' &&
           rest.find_first_of("@?#\\") == rest.npos &&
           std::ranges::all_of(rest, [](unsigned char c) { return c > 32 && c < 127; });
}

// The caller's hint selects home versus the privileged fallback; configuration picks the fallback mechanism.
inline Config parse_config(std::string_view text, CertificateSource source = CertificateSource::Enrollment)
{
    static constexpr std::array<std::string_view, 19> keys{"enabled",
                                                           "domain",
                                                           "realm",
                                                           "netbios",
                                                           "template_oid",
                                                           "ces_url",
                                                           "ces_auth",
                                                           "service_principal",
                                                           "mechanism",
                                                           "kt_dc_url",
                                                           "certificate_cn",
                                                           "require_full_tgt_lifetime",
                                                           "tgt_seconds",
                                                           "renew_seconds",
                                                           "gc_url",
                                                           "gc_base_dn",
                                                           "cert_remaining_max_seconds",
                                                           "cert_total_max_seconds",
                                                           "minimum_interval_seconds"};
    std::map<std::string, std::string, std::less<>> values;
    std::istringstream in{std::string(text)};
    for (std::string line; std::getline(in, line);)
    {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        const auto equals = line.find('=');
        need(equals != line.npos, "config line needs key=value");
        const auto key = trim(line.substr(0, equals)), value = trim(line.substr(equals + 1));
        if (std::ranges::find(keys, key) == keys.end())
            fail("unknown config key: " + sanitize_ascii(key, 64));
        if (value.empty()) fail("empty config value: " + key);
        if (!values.emplace(key, value).second) fail("duplicate config key: " + key);
    }
    const auto optional = [&](std::string_view key, std::string fallback)
    {
        const auto found = values.find(key);
        return found == values.end() ? fallback : found->second;
    };
    const auto required = [&](std::string_view key, bool wanted = true)
    {
        const auto found = values.find(key);
        if (wanted && found == values.end()) fail(std::format("missing config key: {}", key));
        return wanted ? found->second : std::string{};
    };
    const auto seconds = [&](std::string_view key, uint32_t fallback, uint32_t maximum)
    {
        const auto found = values.find(key);
        return found == values.end() ? fallback : number(found->second, maximum);
    };
    need(required("enabled") == "yes", "service disabled; review configuration and set enabled=yes");
    if (source != CertificateSource::Home)
    {
        const auto mechanism = optional("mechanism", "enrollment");
        need(mechanism == "enrollment" || mechanism == "key_trust",
             "mechanism must be enrollment or key_trust");
        source = mechanism == "key_trust" ? CertificateSource::KeyTrust : CertificateSource::Enrollment;
    }
    const bool enrollment = source == CertificateSource::Enrollment; // CA, CES and enrollment agent
    const bool key_trust = source == CertificateSource::KeyTrust;    // msDS-KeyCredentialLink
    Config c;
    c.source = source;
    c.domain = required("domain");
    c.realm = required("realm");
    c.netbios = required("netbios", enrollment);
    c.template_oid = required("template_oid", enrollment);
    c.ces_url = required("ces_url", enrollment);
    c.ces_auth = required("ces_auth", enrollment);
    c.service_principal = required("service_principal", enrollment || key_trust); // LDAP/GSSAPI and CES
    c.kt_dc_url = required("kt_dc_url", key_trust);
    c.gc_url = optional("gc_url", "ldap://" + c.domain + ":3268");
    c.gc_base_dn = optional("gc_base_dn", domain_to_dn(c.domain));
    c.certificate_cn = optional("certificate_cn", c.certificate_cn);
    c.tgt = seconds("tgt_seconds", c.tgt, 604800);
    c.renew = seconds("renew_seconds", c.renew, 604800);
    c.cert_remaining = seconds("cert_remaining_max_seconds", c.cert_remaining, 86400);
    c.cert_total = seconds("cert_total_max_seconds", c.cert_total, 86400);
    c.interval = seconds("minimum_interval_seconds", c.interval, 86400);
    const auto full = optional("require_full_tgt_lifetime", "yes");
    need(full == "yes" || full == "no", "require_full_tgt_lifetime must be yes or no");
    c.require_full_tgt_lifetime = full == "yes";

    static const std::regex domain_re(
        R"(^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$)");
    static const std::regex realm_re(
        R"(^[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)*$)");
    static const std::regex oid_re(R"(^[0-2](?:\.(?:0|[1-9][0-9]*))+$)");
    need(c.domain.size() < 254 && c.realm.size() < 254, "domain value too long");
    need(std::regex_match(c.domain, domain_re), "domain must be lowercase DNS syntax");
    need(std::regex_match(c.realm, realm_re), "realm must be uppercase DNS syntax");
    if (enrollment)
    {
        need(!c.netbios.empty() && c.netbios.size() <= 15 &&
                 c.netbios.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == c.netbios.npos,
             "invalid NetBIOS domain");
        need(c.template_oid.size() < 128 && std::regex_match(c.template_oid, oid_re), "invalid template OID");
        need(c.ces_auth == "negotiate" || c.ces_auth == "mtls", "ces_auth must be negotiate or mtls");
        need(plain_url(c.ces_url, "https://"),
             "ces_url must be an https:// URL without credentials, query or fragment");
    }

    // Directory traffic is protected by the GSSAPI security layer, which Active Directory refuses inside TLS.
    if (key_trust)
        need(plain_url(c.kt_dc_url, "ldap://"),
             "kt_dc_url must be an ldap:// URL naming the writable domain controller");
    if (source != CertificateSource::Home)
        need(plain_url(c.gc_url, "ldap://"), "gc_url must be an ldap:// URL");
    need(c.certificate_cn.size() <= 256, "certificate CN pattern is too long");
    need(c.tgt >= 60 && (c.renew == 0 || c.renew >= c.tgt) && c.cert_remaining >= 60 &&
             c.cert_total >= c.cert_remaining && c.interval >= 30,
         "invalid lifetime/rate limits");
    return c;
}

inline Config config(CertificateSource source = CertificateSource::Enrollment)
{
    return parse_config(root_text(path("config")), source);
}

// Expand only administrator-configured CN placeholders; identity still comes from the directory UPN.
inline std::string common_name(const Config &cfg, std::string_view user, std::string_view upn)
{
    std::string cn;
    const std::string_view pattern = cfg.certificate_cn;
    for (size_t pos = 0; pos < pattern.size();)
    {
        if (pattern[pos] != '{')
        {
            cn += pattern[pos++];
            continue;
        }
        const auto end = pattern.find('}', pos);
        const auto token = pattern.substr(pos, end == pattern.npos ? pattern.npos : end - pos + 1);
        if (token == "{user}") cn += user;
        else if (token == "{upn}") cn += upn;
        else if (token == "{domain}") cn += cfg.domain;
        else fail("unknown certificate CN placeholder");
        pos = end + 1;
    }
    need(!cn.empty() && cn.size() <= 64 && cn.find_first_of("{}") == cn.npos &&
             std::ranges::all_of(cn, [](unsigned char c) { return c >= 32 && c < 127; }),
         "certificate CN must expand to 1..64 printable ASCII characters without braces");
    return cn;
}

} // namespace craft

#pragma once

// Enrollment on behalf of the caller: PKCS#10 request, enrollment-agent CMS, WSTEP SOAP and the CES exchange.
#include "x509.hpp"
#include <openssl/cms.h>
#include <curl/curl.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

namespace craft
{
using Req = Owned<X509_REQ, X509_REQ_free>;
using Cms = Owned<CMS_ContentInfo, CMS_ContentInfo_free>;

inline void free_xml(xmlChar *value) noexcept
{
    xmlFree(value);
}

using XmlText = Owned<xmlChar, free_xml>;
using XmlDoc = Owned<xmlDoc, xmlFreeDoc>;
inline constexpr char ENROLL_PAIR_OID[] = "1.3.6.1.4.1.311.13.2.1";
inline constexpr char SOAP_NS[] = "http://www.w3.org/2003/05/soap-envelope";
inline constexpr char TRUST_NS[] = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
inline constexpr char SECURITY_NS[] =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
inline constexpr char X509_TOKEN[] =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
inline constexpr char ENROLL_NS[] = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";

inline std::string base64(ByteView b)
{
    need(b.size() <= MAX_BLOB, "base64 input too large");
    std::string s(4 * ((b.size() + 2) / 3) + 1, '\0');
    const int n =
        EVP_EncodeBlock(reinterpret_cast<unsigned char *>(s.data()), b.data(), static_cast<int>(b.size()));
    sslneed(n >= 0, "base64 encode");
    s.resize(static_cast<size_t>(n));
    return s;
}

inline Bytes unbase64(std::string s)
{
    // Strip permitted whitespace, then reject anything outside the alphabet and trailing padding.
    need(s.size() <= 2 * MAX_BLOB, "invalid base64 length");
    std::erase_if(s, [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; });
    need(!s.empty() && s.size() % 4 == 0, "invalid base64 length");
    const size_t padding = (s.back() == '=') + (s[s.size() - 2] == '=');
    const std::string_view payload(s.data(), s.size() - padding);
    need(payload.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") ==
             std::string_view::npos,
         "invalid base64 character");
    Bytes b(s.size() / 4 * 3);
    const int n = EVP_DecodeBlock(
        b.data(), reinterpret_cast<const unsigned char *>(s.data()), static_cast<int>(s.size()));
    sslneed(n >= 0 && static_cast<size_t>(n) >= padding, "base64 decode");
    b.resize(static_cast<size_t>(n) - padding);
    return b;
}

inline Bytes bmp(std::string_view s)
{
    Bytes b;
    for (const unsigned char ch : s)
    {
        need(ch >= 32 && ch < 127, "non-ASCII enrollment attribute");
        b.push_back(0);
        b.push_back(ch);
    }
    return der(0x1e, b);
}

// Request a non-CA PKINIT leaf for the pinned template; the CA remains authoritative for the issued subject
// and supplies the SID, never the enrollee.
inline Req
make_request(EVP_PKEY *key, std::string_view upn, const std::string &template_id, std::string_view cn)
{
    Req req(X509_REQ_new());
    const Name name = common_name_only(cn);
    sslneed(req && X509_REQ_set_version(req.get(), 0) == 1 && X509_REQ_set_pubkey(req.get(), key) == 1 &&
                X509_REQ_set_subject_name(req.get(), name.get()) == 1,
            "CSR initialize");
    Extensions exts(sk_X509_EXTENSION_new_null());
    sslneed(exts != nullptr, "CSR extension stack");
    const auto add = [&](Ext e)
    {
        sslneed(sk_X509_EXTENSION_push(exts.get(), e.get()) > 0, "CSR extension append");
        (void)e.release();
    };
    add(upn_extension(upn));
    add(raw_extension(TEMPLATE_OID, der(0x30, join(oid_der(template_id), der(0x02, Bytes{1})))));
    add(conf_extension(NID_basic_constraints, "critical,CA:FALSE"));
    add(conf_extension(NID_key_usage, "critical,digitalSignature,keyEncipherment"));
    add(logon_eku_extension());
    sslneed(X509_REQ_add_extensions(req.get(), exts.get()) == 1, "CSR add extensions");
    sslneed(X509_REQ_sign(req.get(), key, EVP_sha256()) > 0, "CSR self-signature");
    return req;
}

// Serialize any i2d-encodable OpenSSL object to DER.
template <class T, class Encode> inline Bytes to_der(T *object, Encode encode, std::string_view what)
{
    const int n = encode(object, nullptr);
    sslneed(n > 0, what);
    Bytes b(static_cast<size_t>(n));
    auto p = b.data();
    sslneed(encode(object, &p) == n, what);
    return b;
}

inline Bytes request_der(X509_REQ *req)
{
    return to_der(req, i2d_X509_REQ, "CSR DER");
}

// Sign enrollment on behalf of the fixed requester using the enrollment-agent key.
inline Bytes wrap_eobo(X509_REQ *req, X509 *agent, EVP_PKEY *agent_key, std::string_view requester)
{
    const Bytes csr = request_der(req);
    const Bio data = membio(csr);
    Cms cms(CMS_sign(nullptr, nullptr, nullptr, nullptr, CMS_BINARY | CMS_PARTIAL));
    sslneed(cms != nullptr, "CMS initialize");
    CMS_SignerInfo *signer = CMS_add1_signer(cms.get(), agent, agent_key, EVP_sha256(), CMS_NOSMIMECAP);
    sslneed(signer != nullptr, "CMS enrollment-agent signer");

    // The signed attribute is a SET holding one SEQUENCE { BMPString name, BMPString value }.
    const Bytes pair = der(0x30, join(bmp("requestername"), bmp(requester)));
    const Obj oid(OBJ_txt2obj(ENROLL_PAIR_OID, 1));
    sslneed(oid && CMS_signed_add1_attr_by_OBJ(
                       signer, oid.get(), V_ASN1_SEQUENCE, pair.data(), static_cast<int>(pair.size())) == 1,
            "CMS signed requestername");
    sslneed(CMS_final(cms.get(), data.get(), nullptr, CMS_BINARY) == 1, "CMS sign");
    return to_der(cms.get(), i2d_CMS_ContentInfo, "CMS DER");
}

inline std::string xml_escape(std::string_view s)
{
    std::string out;
    for (const char c : s)
    {
        need(static_cast<unsigned char>(c) >= 32, "control in XML text");
        if (c == '&') out += "&amp;";
        else if (c == '<') out += "&lt;";
        else if (c == '>') out += "&gt;";
        else if (c == '"') out += "&quot;";
        else if (c == '\'') out += "&apos;";
        else out += c;
    }
    return out;
}

inline std::string random_uuid()
{
    // RFC 4122 version 4: random bits around the fixed version and variant fields.
    Bytes b = random_bytes(16);
    b[6] = static_cast<unsigned char>((b[6] & 0x0f) | 0x40);
    b[8] = static_cast<unsigned char>((b[8] & 0x3f) | 0x80);
    const auto h = hex(b);
    return std::format(
        "{}-{}-{}-{}-{}", h.substr(0, 8), h.substr(8, 4), h.substr(12, 4), h.substr(16, 4), h.substr(20));
}

// Construct the WSTEP request; the complete CMS, including the signed requestername, is the PKCS7 token.
inline std::string soap_request(const Config &c, ByteView cms)
{
    return std::format(
        R"(<?xml version="1.0" encoding="utf-8"?>)"
        R"(<s:Envelope xmlns:s="{0}" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:t="{1}")"
        R"( xmlns:o="{2}" xmlns:e="{3}"><s:Header>)"
        R"(<a:Action s:mustUnderstand="1">{3}/RST/wstep</a:Action>)"
        R"(<a:MessageID>urn:uuid:{4}</a:MessageID>)"
        R"(<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>)"
        R"(<a:To s:mustUnderstand="1">{5}</a:To></s:Header><s:Body><t:RequestSecurityToken>)"
        R"(<t:TokenType>{6}</t:TokenType><t:RequestType>{1}/Issue</t:RequestType>)"
        R"(<o:BinarySecurityToken ValueType="{2}#PKCS7" EncodingType="{2}#base64binary">)"
        R"({7}</o:BinarySecurityToken>)"
        R"(<e:RequestID xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>)"
        R"(</t:RequestSecurityToken></s:Body></s:Envelope>)",
        SOAP_NS,
        TRUST_NS,
        SECURITY_NS,
        ENROLL_NS,
        random_uuid(),
        xml_escape(c.ces_url),
        X509_TOKEN,
        base64(cms));
}

inline xmlNodePtr one(xmlDocPtr doc, const char *expr, bool required = true)
{
    Owned<xmlXPathContext, xmlXPathFreeContext> ctx(xmlXPathNewContext(doc));
    need(ctx != nullptr, "XML XPath context");
    need(xmlXPathRegisterNs(ctx.get(), BAD_CAST "s", BAD_CAST SOAP_NS) == 0 &&
             xmlXPathRegisterNs(ctx.get(), BAD_CAST "t", BAD_CAST TRUST_NS) == 0 &&
             xmlXPathRegisterNs(ctx.get(), BAD_CAST "o", BAD_CAST SECURITY_NS) == 0,
         "XML namespaces");
    Owned<xmlXPathObject, xmlXPathFreeObject> res(xmlXPathEvalExpression(BAD_CAST expr, ctx.get()));
    need(res != nullptr, "XPath evaluation");
    const int n = res->nodesetval ? res->nodesetval->nodeNr : 0;
    need(n <= 1 && (!required || n == 1), "missing or ambiguous SOAP element");
    return n ? res->nodesetval->nodeTab[0] : nullptr;
}

inline std::string node_text(xmlNodePtr node)
{
    XmlText text(xmlNodeGetContent(node));
    need(text != nullptr, "empty XML text");
    return reinterpret_cast<const char *>(text.get());
}

// Parse a bounded response with DTDs, entities, network access and huge-document mode all refused.
inline XmlDoc parse_soap(const std::string &body)
{
    need(body.size() <= 2 * MAX_BLOB, "SOAP response exceeds limit");
    need(body.find("<!DOCTYPE") == std::string::npos && body.find("<!ENTITY") == std::string::npos,
         "DTD/entity declarations are forbidden");
    XmlDoc doc(xmlReadMemory(body.data(),
                             static_cast<int>(body.size()),
                             "response.xml",
                             nullptr,
                             XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING));
    need(doc && !doc->intSubset && !doc->extSubset, "invalid SOAP XML or forbidden DTD");
    return doc;
}

inline void reject_fault(xmlDocPtr doc)
{
    if (const auto fault = one(doc, "/s:Envelope/s:Body/s:Fault", false))
        fail("CES SOAP fault: " + sanitize_ascii(node_text(fault)));
}

// Require a unique issued certificate for the generated key.
inline Cert parse_response(const std::string &body, EVP_PKEY *expected_key)
{
    const auto doc = parse_soap(body);
    reject_fault(doc.get());
    const char *expr =
        "/s:Envelope/s:Body/t:RequestSecurityTokenResponseCollection/t:RequestSecurityTokenResponse/"
        "t:RequestedSecurityToken/o:BinarySecurityToken | "
        "/s:Envelope/s:Body/t:RequestSecurityTokenResponse/t:RequestedSecurityToken/o:BinarySecurityToken";
    const auto token = one(doc.get(), expr, false);
    need(token != nullptr,
         "CES returned no issued certificate (possibly pending/denied); inspect CA/CES logs; pending polling "
         "is not implemented");
    const auto property = [&](const char *name)
    {
        XmlText value(xmlGetProp(token, BAD_CAST name));
        return value ? std::string(reinterpret_cast<const char *>(value.get())) : std::string{};
    };
    const auto encoding = property("EncodingType"), type = property("ValueType");
    need(encoding == std::string(SECURITY_NS) + "#base64binary", "unsupported certificate token encoding");
    const Bytes data = unbase64(node_text(token));
    const unsigned char *p = data.data();
    if (type == X509_TOKEN)
    {
        Cert c(d2i_X509(nullptr, &p, static_cast<long>(data.size())));
        sslneed(c && p == data.data() + data.size(), "parse issued X509 certificate");
        return c;
    }
    need(type == std::string(SECURITY_NS) + "#PKCS7", "unsupported certificate token type");
    Cms cms(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(data.size())));
    sslneed(cms && p == data.data() + data.size(), "parse issued CMS chain");
    Certificates certs(CMS_get1_certs(cms.get()));
    sslneed(certs != nullptr, "issued CMS has no certificates");
    Cert result;
    int count = 0;
    for (int i = 0; i < sk_X509_num(certs.get()); ++i)
    {
        X509 *c = sk_X509_value(certs.get(), i);
        const Key pub(X509_get_pubkey(c));
        if (!pub || EVP_PKEY_eq(pub.get(), expected_key) != 1) continue;
        sslneed(X509_up_ref(c) == 1, "certificate reference");
        result.reset(c);
        ++count;
    }
    need(count == 1, "response must contain exactly one certificate for the new key");
    return result;
}

inline size_t receive(void *p, size_t size, size_t nmemb, void *target) noexcept
{
    auto &b = *static_cast<std::string *>(target);
    if (size && nmemb > SIZE_MAX / size) return 0;
    const size_t n = size * nmemb;
    if (n > 2 * MAX_BLOB - b.size()) return 0;
    try
    {
        b.append(static_cast<char *>(p), n);
    }
    catch (...)
    {
        return 0;
    }
    return n;
}

// Submit enrollment over verified HTTPS using the configured transport identity; returns the response body.
inline std::string send_ces(const Config &cfg, const std::string &request)
{
    const auto trust = path("https-trust.pem"), crls = path("https-crls.pem");
    root_open(trust);
    Owned<CURL, curl_easy_cleanup> c(curl_easy_init());
    need(c != nullptr, "curl handle");
    std::string response;
    char error[CURL_ERROR_SIZE]{};
    const auto opt = [&](CURLoption o, auto value)
    {
        need(curl_easy_setopt(c.get(), o, value) == CURLE_OK, "curl option rejected");
    };

    // parse_config already restricted the URL to plain https://host[:port][/path].
    opt(CURLOPT_URL, cfg.ces_url.c_str());
    opt(CURLOPT_POST, 1L);
    opt(CURLOPT_POSTFIELDS, request.c_str());
    opt(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.size()));
    opt(CURLOPT_SSL_VERIFYPEER, 1L);
    opt(CURLOPT_SSL_VERIFYHOST, 2L);
    opt(CURLOPT_CAINFO, trust.c_str());
    opt(CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
    opt(CURLOPT_FOLLOWLOCATION, 0L);
    opt(CURLOPT_PROXY, "");
    opt(CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED));
    opt(CURLOPT_CONNECTTIMEOUT, 10L);
    opt(CURLOPT_TIMEOUT, 40L);
    opt(CURLOPT_NOSIGNAL, 1L);
    opt(CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_1_1));
    opt(CURLOPT_WRITEFUNCTION, receive);
    opt(CURLOPT_WRITEDATA, &response);
    opt(CURLOPT_ERRORBUFFER, error);

    // Trust only the pinned bundle: some libcurl builds would otherwise also consult a system CA directory.
    const auto capath = curl_easy_setopt(c.get(), CURLOPT_CAPATH, static_cast<char *>(nullptr));
    need(capath == CURLE_OK || capath == CURLE_NOT_BUILT_IN, "curl CA directory option rejected");

    // An optional CRL bundle enforces revocation for the whole CES server chain.
    if (access(crls.c_str(), F_OK) == 0)
    {
        root_open(crls);
        opt(CURLOPT_CRLFILE, crls.c_str());
    }

    // Permit only configured Negotiate or mTLS; CES must disallow GSS NTLM fallback.
    if (cfg.ces_auth == "negotiate")
    {
        need(curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_SPNEGO,
             "libcurl lacks SPNEGO; use a distribution libcurl with GSSAPI/MIT Kerberos support");
        opt(CURLOPT_HTTPAUTH, static_cast<long>(CURLAUTH_NEGOTIATE));
        opt(CURLOPT_USERPWD, ":");
        opt(CURLOPT_GSSAPI_DELEGATION, static_cast<long>(CURLGSSAPI_DELEGATION_NONE));
    }
    else
    {
        const auto certificate = path("https-client.pem"), key = path("https-client.key");
        root_open(certificate);
        root_open(key, Trusted::Secret);
        opt(CURLOPT_SSLCERT, certificate.c_str());
        opt(CURLOPT_SSLKEY, key.c_str());
    }
    Owned<curl_slist, curl_slist_free_all> headers;
    for (const auto text : {"Content-Type: application/soap+xml; charset=utf-8", "Expect:"})
    {
        auto *appended = curl_slist_append(headers.get(), text);
        need(appended != nullptr, "HTTP headers");
        (void)headers.release();
        headers.reset(appended);
    }
    opt(CURLOPT_HTTPHEADER, headers.get());
    if (curl_easy_perform(c.get()) != CURLE_OK) fail("CES HTTPS failure: " + sanitize_ascii(error));
    long status = 0;
    need(curl_easy_getinfo(c.get(), CURLINFO_RESPONSE_CODE, &status) == CURLE_OK, "HTTP response status");

    // SOAP faults commonly arrive as HTTP 500: report the fault, and never accept credentials from one.
    if (status == 500)
    {
        reject_fault(parse_soap(response).get());
        fail("CES HTTP 500; inspect CA/CES logs");
    }
    if (status != 200)
        fail(std::format("CES HTTP status {} (check endpoint, TLS mapping, SPN and authentication)", status));
    return response;
}

} // namespace craft

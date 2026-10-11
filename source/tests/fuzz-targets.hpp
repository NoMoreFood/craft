#pragma once

// The parsers the fuzzer exercises. The first byte of an input selects one, so the seed corpus that
// `craft-tests --fuzz-seeds` writes and the harness in fuzz.cpp must agree on this order.
namespace craft::testing
{
enum class FuzzTarget : unsigned char
{
    Config,     // parse_config for the privileged fallback
    HomeConfig, // parse_config for a supplied home pair
    Response,   // the CES SOAP response and the certificate inside it
    Base64,
    Extension, // the subjectAltName and template extensions, decoded by hand
    Pem,       // a supplied PEM certificate or key
    Der,       // a DER certificate from the CA
    Ticket,    // the outer Kerberos ticket
    Options,   // craft-maintain's command line
    Record,    // a state record
    Text,      // names, URLs and the certificate CN pattern
    ProcStat,  // /proc/<pid>/stat of the watched job
    Count
};
} // namespace craft::testing

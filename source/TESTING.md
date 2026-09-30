# CRAFT Validation Status and Acceptance Tests

## Offline Coverage

The test executable contains synthetic checks for parsing, cryptography, ownership and ticket policy. CTest registers it as one test; run `craft-tests` directly to see individual check results and the current count. Record the commit, compiler/library versions, commands and output for each validation run instead of treating a previous test count as evidence for the current tree.

The synthetic fixtures cover:

- CSR self-signature and requested CN, UPN, template, three client EKUs and non-CA usage; CMS signature, embedded CSR and signed requestername.
- Pinned UPN/SID/template/key checks; missing/duplicate/malformed identities, missing client EKUs, non-CA constraints, wrong usage, expiry and ten-hour validity caps.
- Dynamic Global Catalog settings parsing, domain-to-DN formatting, binary SID parsing and validation, integer bounds, configuration flags and custom CN substitutions.
- Ten-hour requested/granted initial lifetime, seven-day renewal lifetime checks, strict short-grant refusal and explicit shorter-grant warnings; renewable and non-renewable validation; ticket flags, principal, key length and AES128/AES256 session/envelope validation; RC4 rejection.
- Exception-safe C output adoption, resource ownership, secret-buffer erasure, bounded I/O, sealed memfd behavior, WSTEP parsing and malformed/DTD/oversized responses.
- Version-4 FILE cache serialization read back by MIT Kerberos.
- Maintainer options/scheduling, renewal validation, service-ticket preservation, atomic publication, locking and job-exit tracking.

The test tickets use the literal marker `NOT-A-REAL-TICKET` as ciphertext. These are local parser/policy fixtures, not forged working tickets, authenticated Kerberos exchanges or proof that a Windows KDC grants the requested lifetime. No real user credentials, CA enrollment or domain-controller traffic was used.

Offline tests do not exercise LDAP/GSSAPI, live EOBO/CES, Windows SID issuance, real-PKI CRL chains, memfd-backed PKINIT, effective DC policy, or ten-hour-certificate/ten-hour-TGT/seven-day-renewal interoperability. They also do not exercise the installed setuid/fexecve/drop boundary. Validate those separately in a configured lab; offline success does not establish production readiness.

## Build and Unit Tests

On Linux, install the [build and runtime dependencies](README.md#build) and run from `source/`.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/craft-tests
```

Optional address/undefined-behavior sanitizer build (do not install sanitizer binaries setuid):

```sh
cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-sanitize -j2
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
./build-sanitize/craft-tests
```

## Detached-maintainer integration checks

The native `craft-maintain-tests` harness uses synthetic caches and an issuer copied from `craft-tests`.
Run it separately from CTest in a disposable Linux container; it refuses ordinary accounts or mismatched issuers.
After building, prepare and run it inside that container:

```sh
useradd --create-home --shell /bin/sh craft-maintain-test
chmod 0700 /home/craft-maintain-test
install -o root -g root -m 0755 build/craft-tests /usr/local/bin/craft
printf '[libdefaults]\n dns_lookup_kdc = false\n udp_preference_limit = 1\n[realms]\n DOMAIN.LOCAL = {\n  kdc = 127.0.0.1:9\n }\n' > /etc/krb5.conf
runuser -u craft-maintain-test -- build/craft-maintain-tests build/craft-maintain build/craft-tests
```

Checks cover startup/closed pipes, status, job-exit/duration cleanup, credential expiry/rollover, concurrent starts,
shared backoff, cancellation and unsafe caches. The KDC address intentionally refuses connections to verify renewal
failures preserve credentials without enrollment. These checks establish lifecycle behavior, not live renewal success.

## Maintainer Validation — September 30, 2026

Validated the uncommitted working tree based on `c1f857c` in a disposable Ubuntu 24.04 container with GCC 13.3,
MIT Kerberos 1.20.1, OpenSSL 3.0.13, libcurl 8.5.0, libxml2 2.9.14, OpenLDAP 2.6.10 and Cyrus SASL 2.1.28.

- Release/CTest: 78 offline checks passed; AddressSanitizer passed with leak detection.
- Native harness: 15 checks and account/issuer guards passed with address/undefined-behavior sanitizers
  and only the documented build dependencies.
- MIT KDC: a ten-second AES256 TGT with a sixty-second renewal window renewed twice, retaining the deadline and
  a usable service ticket after the bootstrap keytab was removed. The disabled issuer was never called;
  job exit stopped maintenance.

AD CS/PKINIT renewal after certificate expiry, full renewal-window rollover and the actual scheduler/application
still require live acceptance testing.

## Windows Helper Checks

From the repository root in PowerShell, run the offline parameter, native-command and certificate-selection checks:

```powershell
.\scripts\Test-Configure-CRAFT-CA.ps1
```

These checks do not provision AD objects, enroll certificates, configure a CA or validate a live Windows deployment.

## Hyper-V Lab Run — September 27, 2026

Tested source commit `514b851` and updated DISA STIG configuration on the two-node Hyper-V lab environment: Windows Server 2022 Datacenter DC (`CRAFT-DC`, `192.168.100.10`, domain `craft.lab`) and Ubuntu 24.04 LTS client (`CRAFT-Linux`, `192.168.100.20`, user `alice`).

1. **CA and Template Configuration:** Configured Schema V2 template `CRAFTUser` with 10-hour validity (`$ValidityHours = 10`), RSA-3072 key size, Smart Card Logon, Client Auth, and PKINIT Client Auth EKUs, and 1 Enrollment Agent signature requirement.
2. **KDC DISA STIG Policies:** Verified domain controller Kerberos policy matching DISA STIG: `MaxTicketAge = 10` hours, `MaxRenewAge = 7` days, `MaxServiceAge = 600` minutes, `MaxClockSkew = 5` minutes.
3. **Automated CRAFT Execution:** Invoked setuid launcher `/usr/local/bin/craft` as unprivileged user `alice`. Execution completed in 455 ms without warnings under strict mode (`require_full_tgt_lifetime=yes`).
4. **Ticket Inspection (`klist -ef`):**
   - Initial validity: exactly 10 hours (`09/27/26 01:51:51` to `09/27/26 11:51:51`).
   - Renewal window: exactly 7 days (`renew until 10/04/26 01:51:51`).
   - Flags: `RIA` (`Renewable`, `Initial`, `Pre-authenticated`).
   - Encryption: pure AES-256 for both session key (`skey`) and ticket envelope (`tkt`).
5. **Directory and Service Authentication:**
   - Active Directory LDAP search authenticated via GSSAPI (`SASL username: alice@CRAFT.LAB`, `SASL SSF: 256`).
   - Domain Controller SMB shares (`//CRAFT-DC.craft.lab`) authenticated successfully using Kerberos.
6. **Ticket Renewal:** Renewed the issued ticket against the KDC via `kinit -R -c $KRB5CCNAME`; renewal succeeded without re-prompting, extending expiration to `11:51:11` while retaining the 7-day renew window.

## Live Acceptance Checklist

1. Review the privilege boundary, parsers, trust-chain policy and this host's authority over AD identities. Start with a disposable, nonprivileged account in a lab domain; enforce CA-side template and recipient restrictions.
2. Verify the GC host/search base, `ldap/hostname` SPN and SASL GSSAPI module. Test `service_principal` and `submitter.keytab` with both CES modes, including missing/ambiguous users and alternate UPN suffixes. Confirm CES URL, TLS trust and transport-account access. For Negotiate, verify libcurl SPNEGO/MIT Kerberos, HTTP SPN and CES-to-CA constrained delegation; for mTLS, verify the separate client certificate mapping.
3. Confirm CA audit records identify the intended requester and template, and reject recipients outside the approved group. Inspect the issued UPN, actual recipient SID, template OID, key, three EKUs, key usage, CN behavior, trust chain, CRLs and total validity including backdating. Verify EOBO subject construction.
4. Test the MIT PKINIT plugin against the designated DC, expected hostname, trust anchors and current CRLs. Confirm strong certificate mapping and the resulting user principal. Investigate rejections without weakening policy.
5. Set the lab DC user-ticket lifetime policy to permit 10 hours (`MaxTicketAge = 10 hours`) and renewal to 7 days (`MaxRenewAge = 7 days`), matching DISA STIG guidance. Determine whether PKINIT permits a TGT matching the ten-hour certificate/key lifetime. Verify strict rejection of shorter grants and explicit warnings when shorter grants are allowed; neither mode changes the issued ticket.
6. Invoke the installed launcher directly as the approved user. Inspect ownership/mode and run `klist -ef -c FILE:/actual/home/.krb5cc_craft`. Check actual start/end time, renewable/nonforwardable/nonproxiable flags, renewal expiry, AES session key and ticket encryption. Confirm a real application obtains a service ticket.
7. Verify unknown AD users, CLI overrides, forged environment values, service/root UID invocation, changed UID/name mappings, wrong SID/template/key, missing EKUs, expired CRLs, RC4 and excessive certificate validity fail without replacing a valid cache.
8. Exercise the installed setuid/fexecve/drop boundary, concurrent calls, process termination, timeouts, network failure, caller-home symlinks and writable/renamed homes. Confirm other UIDs cannot read the cache.
9. Test `craft-maintain` with the actual scheduler/application: renewal after certificate expiry, renewal-window rollover, KDC/CES outages, concurrent jobs and reconnects. Confirm maintenance lasts for the job and stops with its watched PID; check status and certificate issuance counts.
10. Review AUTHPRIV/CA/CES/KDC logs. Document CRL refresh, credential rotation, account lifecycle, CA capacity, cache exclusions from backups, ticket expiry, operational disable and incident-response procedures.

Do not keep increasing lifetime caps simply to accommodate an unexpectedly long-lived default template. Review and fix the CA-side short-lived issuance policy.

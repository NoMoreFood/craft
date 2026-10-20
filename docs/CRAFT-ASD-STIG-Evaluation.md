# CRAFT - DISA Application Security and Development (ASD) STIG Assessment

> **Target**: CRAFT Linux reference implementation and optional credential maintainer  
> **Benchmark**: Application Security and Development STIG, Version 6, Release 5  
> **Benchmark Date**: 30 September 2026  
> **Assessment Basis**: Repository source and recorded validation, with fully STIG-compliant OSs and AD assumed; no independent host assessment  
> **Revised**: 11 October 2026, for source commit `c107bef` and the system owner's determinations in section 1  
> **Overall Status**: Incomplete - 0 Open, 50 Not Reviewed, 109 Not a Finding, 127 Not Applicable

## 1. Scope and assessment method

This assessment covers the Linux acquisition paths and `craft-maintain`, with repository guides and provisioning/export helpers as configuration context. Each of the 286 benchmark rules has a disposition, a source/evidence basis and any required follow-up. The accompanying [STIG Viewer checklist](CRAFT-ASD-STIG-Checklist.ckl) contains the full official rule discussion, check and fix text. Neither artifact certifies an installed system or constitutes an authorization to operate.

The assessment and checklist cover Enrollment Agent, Key Trust and BYOC. Broker constrained delegation and configurable multi-mode fallback are outside their assessed scope and require review of authorization, credential handling and operating controls before applying these dispositions to those workflows. A finding affecting one mode keeps the aggregate assessment open; a deployment that excludes that mode must document its narrower scope. Development-process controls remain in scope for this source project. The underlying operating systems and Active Directory are assumed to satisfy their applicable STIGs. Where CRAFT uses the governed platform mechanism and its controls meet the ASD criterion, the item is closed through inheritance or the benchmark's explicit enterprise-manager exemption. These closures rely on the supplied assessment assumption; they are not claims of independently observed host configuration.

Existing [validation notes](../source/TESTING.md) include synthetic/offline checks and limited lab observations. They are evidence for their recorded scope, not proof that the current source, all modes, production PKI, delegated directory rights or operational policies satisfy every check. This review does not rerun live AD/CES/KDC acceptance tests or perform a comprehensive vulnerability assessment. The parser fuzzing and the live MIT KDC runs of 11 October 2026 are recorded there.

| Checklist status | Meaning in this assessment |
| --- | --- |
| `Open` | An identified implementation or documented verification gap fails the assessed requirement; the item states the gap and closure evidence. |
| `Not_Reviewed` | A required deployment, policy, test or process fact has not been established. This is neither compliance nor a confirmed deployed failure. |
| `NotAFinding` | Cited source behavior or inherited OS/AD controls satisfy the assessed check within the stated scope and assumptions. Each inheritance closure identifies its platform basis. |
| `Not_Applicable` | The architecture lacks the addressed feature, or an explicit benchmark exemption is met. Enterprise-manager exemptions can rely on the accepted OS/AD compliance assumption. |

No compliance percentage is calculated while applicable controls remain unreviewed. Platform compliance covers governed host/domain mechanisms. Under the system owner's determinations below, a control whose mechanism lives in the OS or Active Directory is deferred to that platform and says so; it is not held open for CRAFT-specific evidence. Data-classification decisions, deployed PKI tests and development-process records are not platform mechanisms and remain stated separately.

### Inherited OS/AD controls

**106 controls** rely on the platform assumption for inherited mechanisms or explicit enterprise exemptions. Each item records its inherited basis. Enterprise identity-management and centralized-offload exemptions use `Not_Applicable` where the official check requires that disposition; supported host/domain mechanisms use `NotAFinding`.

| Inherited mechanism | ASD controls |
| --- | --- |
| Host/AD account lifecycle and necessary accounts | V-222407, V-222409, V-222412, V-222619, V-222661 |
| Explicit enterprise-account-management exemptions | V-222411, V-222413 through V-222422, V-222467 |
| Privileged execution, event identity and actual authentication results | V-222431, V-222449, V-222462, V-222463 |
| Audit timestamps, source identity, centralized offload/forwarding and backend alarms | V-222446, V-222473, V-222475, V-222481 through V-222485, V-222498 |
| Audit read/write/delete protection and OS library protection | V-222500 through V-222502, V-222514 |
| Local host authentication/MFA and approved native cryptographic mechanisms | V-222528, V-222572, V-222596, V-222641 |
| Host logon and MFA, lockout and non-organizational identities | V-222410, V-222432, V-222433, V-222523 through V-222527, V-222556 through V-222560 |
| Host access control, AD CS restrictions and directory delegation | V-222425, V-222427 through V-222430, V-222516 |
| Host audit and logging: file, connection and configuration-change records, non-repudiation and the response to audit failure | V-222438, V-222451, V-222465, V-222470, V-222471, V-222486, V-222512, V-222586 |
| Centralized log management, integrity, retention and review | V-222480, V-222487 through V-222495, V-222507, V-222621 through V-222623 |
| Host backup, recovery and storage protection | V-222587 through V-222589, V-222636 through V-222640 |
| Platform cryptography, transport protection and replay resistance | V-222396, V-222397, V-222530, V-222531, V-222571, V-222597 through V-222599 |
| Platform networking, ports, IPv6, redundancy, monitoring and enclave boundary | V-222519, V-222595, V-222628, V-222629, V-222634, V-222668, V-222671 |
| Platform software maintenance and ticket lifetime | V-222549, V-222613, V-222614, V-222627 |

Illustrative mappings are drawn from the official [RHEL 9 STIG](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R9_STIG.zip) and [Windows Server 2022 STIG](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R9_STIG.zip). Their rule identifiers explain the inherited mechanisms; they do not declare the actual OS/version inventory. Equivalent controls from the deployed platforms are covered by the same assessment assumption.

The distinction between infrastructure and application semantics is material. RHEL-09-654070's example rules capture file-open permission failures, not every successful CRAFT key read. RHEL-09-654265's critical audit response covers the audit subsystem, not an application's own submission to the logging service. [Microsoft documents](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136) that directory attribute-change events need an appropriate object/attribute SACL. Likewise, host/AD authentication records close actual logon auditing; they do not describe final CRAFT cache-publication outcomes. Source commit `c107bef` answers these boundaries from both sides: CRAFT now writes its own records for requests, issuance, Key Trust changes, publication and renewal, checks that the host logging service takes each one, and ships example host audit rules for file access, launcher use and outbound connections.

### System-owner determinations

On 11 October 2026 the system owner gave the dispositions below. Each control closed on one of them cites it, and none is an independently observed host configuration.

| Determination | Effect |
| --- | --- |
| Multifactor authentication is inherited from the operating system. Users reach CRAFT from an authenticated host session, and administrators must authenticate with MFA to install or administer it. | The PIV and MFA controls, and the lockout and non-organizational-user controls that follow from host logon, are inherited. |
| CRAFT is maintained on GitHub and distributed as source, with no binaries. | Signed-release and release-hash controls are Not Applicable. |
| Backup and recovery are deferred to the operating-system configuration. | Contingency, backup, restoration and stored-data protection controls are inherited. |
| Logging is deferred to the operating system. | Central log management, integrity, retention and review are inherited or exempt; CRAFT's part is to write its records and stop when they are not taken. |
| Anything else that can reasonably be deferred to the operating system is deferred and noted. | Host access control, platform cryptography and transport, ports, IPv6, monitoring and software maintenance are inherited, each with its basis. |
| The enrollment SOAP exchange is fixed by the AD CS Certificate Enrollment Web Service (MS-WSTEP), whose binding defines no message-level signature, timestamp or assertion. | The SOAP message-signing and WS-Security controls (V-222398, V-222399, V-222400, V-222402) are Not Applicable, with the constraint recorded in each entry. |

### Assessment totals

| Severity | Total | Not a Finding | Not Applicable | Open | Not Reviewed |
| --- | ---: | ---: | ---: | ---: | ---: |
| CAT I (High) | 34 | 11 | 16 | 0 | 7 |
| CAT II (Medium) | 230 | 97 | 98 | 0 | 35 |
| CAT III (Low) | 22 | 1 | 13 | 0 | 8 |
| **Total** | **286** | **109** | **127** | **0** | **50** |

## 2. Benchmark and authoritative sources

The authoritative source is DISA's [U_ASD_V6R5_STIG.zip](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R5_STIG.zip), containing `U_ASD_STIG_V6R5_Manual-xccdf.xml` and the benchmark overview/revision history. The XCCDF benchmark ID is `Application_Security_Development_STIG`; its release metadata is `Release: 5 Benchmark Date: 30 Sep 2026`. The benchmark contains 34 high, 230 medium and 22 low severity rules. Rule IDs, titles, severities, CCIs, group titles and full checklist text are taken from that XCCDF, including its DoW terminology.

The current password-age control, **V-222545 / APSC-DV-001770**, specifies a **180-day** maximum. It is Not Applicable to the passwordless CRAFT interface. **V-222643 / APSC-DV-003120** explicitly allows Not Applicable when a system processes no sensitive/classified/CUI information and requires no classification markings. This assessment leaves that determination Not Reviewed because the information owner's data scope is not supplied.

Archive SHA-256: `b73e8a74d591982d49cdc9e0c5c0023b37ab87d91f3f3f150d6dab8baa23c435`. The [DISA release announcement](https://www.cyber.mil/stigs/stig-announcements) identifies the Application Security and Development STIG as Version 6, Release 5.

## 3. Architecture and security boundaries

CRAFT obtains a user TGT through PKINIT and publishes a caller-owned mode-0600 `.krb5cc_craft` in the NSS-resolved home. It has no listening web service, browser UI, relational database or application user-account store. It does consume SOAP/WSTEP in enrollment mode, and processes untrusted configuration/identity/certificate/XML/LDAP/Kerberos data; those facts remain relevant to applicability.

1. **Privileged enrollment** generates a software key, signs an enrollment-on-behalf-of CMS request with an agent credential, submits it to CES over verified HTTPS and validates the returned certificate before PKINIT. The complete SOAP envelope is not digitally signed.
2. **Privileged Key Trust** authenticates to a writable DC with LDAP/GSSAPI, adds one temporary public-key credential to the caller's directory object, obtains a TGT and requires cleanup success before returning credential bytes. An independent guardian attempts cleanup after worker failure. Directory/host failure can still leave a residual key; the client certificate is directory-authorized rather than chained to a trusted user CA.
3. **Home certificate** uses a caller-owned certificate and unencrypted PEM key under `~/.config/craft/`. A complete home pair takes priority on every installation; a partial or invalid pair fails instead of selecting a privileged fallback. The files persist after acquisition.

The descriptor-verified worker processes certificates, network data and Kerberos outside root. The launcher reads only the home-selection byte while elevated and drops to the caller before receiving credential bytes or publishing the cache. Membership restrictions on privileged execution come from installed file permissions; CA/AD restrictions come from separately configured authorities. The source does not directly enforce a `craft-users` group-membership check.

RSA generation defaults to 3072 bits and accepts configured 2048, 3072 or 4096 bits. Initial/renewed user-ticket checks restrict session and outer-ticket encryption to AES128/AES256. CES has a TLS 1.2 minimum and peer/hostname validation, with optional `https-crls.pem`. Approved OS cryptographic modules/policies are inherited when CRAFT uses the governed OS libraries; bundled/private modules fall outside that scope. Directory traffic uses a GSSAPI security layer with minimum SSF 128, not LDAP over TLS. CRAFT-specific KDC trust/CRL/EKU/hostname settings still need an approved deployment profile and acceptance evidence.

Mode-0600 caches contain usable session keys without application at-rest encryption. Ticket-envelope encryption does not encrypt the cache's session key. File permissions and sealed memory files do not establish disk/swap encryption or secure erasure, and source memory is not mlocked. A generic OS STIG does not necessarily require encryption of every Linux home/configuration/swap volume or credential backup, so the required application data-protection scope remains an owner decision. Successful cache replacement uses `openat` with exclusive creation and `renameat` under a cache lock; it does not guarantee the absence of every race or host/library attack.

The application's current network acquisition modes use software-backed credentials. Host local-access authentication/MFA is inherited from the compliant OS, but Smart Card Logon EKUs, enrollment-agent authorization and Windows-exported PEM keys do not establish a CAC/PIV hardware token, PIN challenge or a fresh second factor for network issuance. The system owner has determined that this is acceptable because MFA is enforced at host logon; see the determinations in section 1.

## 4. Open findings and closure priorities

No control is Open and 50 are Not Reviewed. None of them is a missing mechanism in the operating system or Active Directory; each needs a decision or a record that only the system owner, the deployment or the development team can supply.

| Area | Controls | Required closure |
| --- | --- | --- |
| Deployment and data profile | V-222393, V-222394, V-222395, V-222423, V-222424, V-222453, V-222457, V-222461, V-222643, V-222664, V-265634 | The information owner's data classification, marking and compartmentalization requirements, and whether classified data or a National Security System is in scope. Most of these become Not Applicable once that is stated. |
| Mode and capability profile | V-222518 | The approved set of modes for the deployment. |
| Log content review | V-222444 | Review of success and failure records from each deployed mode for sensitive data. |
| PKI and CES transport profile | V-222532, V-222534, V-222550, V-222553, V-222584 | The approved trust anchors, CRLs and CES authentication mode, with revoked, untrusted and missing-CRL tests against the deployed KDC and CES. |
| Failure and residual-key handling | V-222585 | Failure tests in each deployed mode and an approved procedure for finding and removing a residual Key Trust value. |
| Hosting designation | V-222635 | The ISSO's criticality designation for the application. |
| Application lifecycle | V-222659, V-222660, V-222669, V-222670 | Decommissioning and user-notification procedures, and an administrator subscribed to the GitHub repository's release and security notifications. |
| Security test evidence | V-222515, V-222567, V-222594, V-222605, V-222606, V-222608, V-222609, V-222612, V-222644, V-222647, V-222648, V-222649, V-222656 | Per-release assessment, code-review and coverage records. The fuzz and sanitizer runs in TESTING.md are evidence toward these but do not complete them. |
| Development and operational records | V-222630, V-222631, V-222632, V-222633, V-222646, V-222650, V-222651, V-222652, V-222653, V-222654, V-222655, V-222657, V-222673 | Configuration-management, change-control, design, threat-model, incident-response and training records of the development team. |

The four enrollment SOAP controls (V-222398, V-222399, V-222400, V-222402) are Not Applicable by the system owner's determination. The AD CS Certificate Enrollment Web Service fixes the [MS-WSTEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/4766a85d-0d18-4fa1-a51f-e5cb98b752ea) message format, so there is no whole-envelope signature, timestamp or assertion for a client to add; the exchange is protected by verified TLS and the enrollment agent's CMS signature. Do not add WS-Security elements to work around this: the service would ignore or reject them. Reassess if the CES protocol changes.

### Closed since the first assessment

The first assessment recorded 17 Open and 117 Not Reviewed controls. Eighty-four have since been closed in three ways.

| Basis | Controls |
| --- | --- |
| Source commit `c107bef`: audit records for requests, issuance, Key Trust changes, publication and renewal; a stop when the host logging service does not take a record; caller-visible summaries with detail kept for the log; a recorded fuzz procedure and run | V-222455, V-222468, V-222469, V-222472, V-222486, V-222600, V-222610, V-222611, V-222624 |
| System-owner determinations of 11 October 2026 (section 1) on MFA, logging, backup, source-only distribution and other platform mechanisms, including the host audit and logging services that complete the controls above | Seventy-one controls, listed with their basis in the inherited-controls table and in each entry |
| System-owner determination that the AD CS CES protocol fixes the enrollment SOAP message format | V-222398, V-222399, V-222400, V-222402 |

Two caveats travel with these closures. The example host audit rules in `source/config/craft.audit.rules` were written to convention and have not been loaded on a live host by this assessment. And five transport controls (V-222396, V-222397, V-222597, V-222598, V-222599) name TLS in their check text, while CRAFT's directory connection uses the GSSAPI security layer that Active Directory requires; an assessor must accept that as the equivalent.

## 5. Control-by-control responses

### 5.1. Open findings (0 controls)

None.

### 5.2. Evidence or applicability pending (50 controls)

#### [V-222393] APSC-DV-000110 - The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage.

- **Rule ID**: `SV-222393r1136904_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002262`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository does not establish the deployed data classification or whether credentials, identity data and diagnostics require security markings. Binary output and the absence of a web UI do not establish the STIG marking exemption. CRAFT does not supply a classification-marking facility.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Obtain the information owner's classification and marking requirements. Use the benchmark's Not Applicable criteria only when the absence of classified/CUI or other marking requirements is established; otherwise demonstrate required markings.

#### [V-222394] APSC-DV-000120 - The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in process.

- **Rule ID**: `SV-222394r1136906_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002263`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository does not establish the deployed data classification or whether credentials, identity data and diagnostics require security markings. Binary output and the absence of a web UI do not establish the STIG marking exemption. CRAFT does not supply a classification-marking facility.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Obtain the information owner's classification and marking requirements. Use the benchmark's Not Applicable criteria only when the absence of classified/CUI or other marking requirements is established; otherwise demonstrate required markings.

#### [V-222395] APSC-DV-000130 - The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.

- **Rule ID**: `SV-222395r1136908_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002264`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository does not establish the deployed data classification or whether credentials, identity data and diagnostics require security markings. Binary output and the absence of a web UI do not establish the STIG marking exemption. CRAFT does not supply a classification-marking facility.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Obtain the information owner's classification and marking requirements. Use the benchmark's Not Applicable criteria only when the absence of classified/CUI or other marking requirements is established; otherwise demonstrate required markings.

#### [V-222423] APSC-DV-000440 - Application data protection requirements must be identified and documented.

- **Rule ID**: `SV-222423r961302_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002346`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Security notes identify sensitive PEM keys, enrollment/service credentials, Kerberos session keys, persistent caches, residual directory keys and swap/host-capture risks. They do not establish the information owner's complete data classification and approved protection requirements for a deployment.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/README.md](../source/README.md); [docs/03-Enrollment-Agent-Restrictions.md](03-Enrollment-Agent-Restrictions.md); [docs/04-Key-Credential-Link-Delegation.md](04-Key-Credential-Link-Delegation.md). Follow-up: Document the data inventory, classification, protection requirements and responsible owners, including at-rest encryption, retention, backups and residual-credential response.

#### [V-222424] APSC-DV-000450 - The application must utilize organization-defined data mining detection techniques for organization-defined data storage objects to adequately detect data mining attempts.

- **Rule ID**: `SV-222424r961305_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002347`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository does not establish organization-defined data-mining, non-repudiation or compartmentalized information requirements. Credential-helper architecture alone does not establish the policy-dependent exemption for this control.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/README.md](../source/README.md). Follow-up: Obtain the applicable information-protection policy and scope decision. Demonstrate the required mechanism and events if applicable, or record the documented basis for Not Applicable.

#### [V-222444] APSC-DV-000650 - The application must not write sensitive data into the application logs.

- **Rule ID**: `SV-222444r960879_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000169`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Intended logging paths do not serialize private keys, ticket ciphertext or session-key bytes. However, sanitized library error strings and CES SOAP fault text are relayed into diagnostics/audit messages. Character filtering is not sensitive-data redaction, and no deployed success/failure log corpus was reviewed.
- **Comments / Evidence**: Evidence: [source/src/worker.cpp](../source/src/worker.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp): reject_fault, send_ces; [source/src/common.hpp](../source/src/common.hpp): sanitize_ascii; [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Inspect realistic success/failure logs from every enabled mode and maintainer, including CES faults and library errors, for credentials and other sensitive data. Use synthetic secrets for negative tests.

#### [V-222453] APSC-DV-000740 - The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.

- **Rule ID**: `SV-222453r961797_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository does not establish organization-defined data-mining, non-repudiation or compartmentalized information requirements. Credential-helper architecture alone does not establish the policy-dependent exemption for this control.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/README.md](../source/README.md). Follow-up: Obtain the applicable information-protection policy and scope decision. Demonstrate the required mechanism and events if applicable, or record the documented basis for Not Applicable.

#### [V-222457] APSC-DV-000780 - The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.

- **Rule ID**: `SV-222457r961809_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository does not establish organization-defined data-mining, non-repudiation or compartmentalized information requirements. Credential-helper architecture alone does not establish the policy-dependent exemption for this control.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/README.md](../source/README.md). Follow-up: Obtain the applicable information-protection policy and scope decision. Demonstrate the required mechanism and events if applicable, or record the documented basis for Not Applicable.

#### [V-222461] APSC-DV-000820 - The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.

- **Rule ID**: `SV-222461r961821_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository does not establish organization-defined data-mining, non-repudiation or compartmentalized information requirements. Credential-helper architecture alone does not establish the policy-dependent exemption for this control.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/README.md](../source/README.md). Follow-up: Obtain the applicable information-protection policy and scope decision. Demonstrate the required mechanism and events if applicable, or record the documented basis for Not Applicable.

#### [V-222515] APSC-DV-001460 - An application vulnerability assessment must be conducted.

- **Rule ID**: `SV-222515r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000366`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository contains synthetic parser/cryptographic/filesystem tests, maintainer failure/race tests and validation notes. These are useful evidence, but they do not establish a current architecture-wide assessment covering this rule's required scan/review scope and all deployed modes/dependencies. Native CLI architecture does not exempt general input validation, XML processing or input-handling controls.
- **Comments / Evidence**: Evidence: [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md); [source/SECURITY.md](../source/SECURITY.md); [source/src/config.hpp](../source/src/config.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/x509.hpp](../source/src/x509.hpp). Follow-up: Supply current source/build-specific assessment settings, results and remediation/risk decisions for this rule. Include realistic malformed input, concurrency, termination and library/remote-error paths as applicable.

#### [V-222518] APSC-DV-001500 - The application must be configured to disable non-essential capabilities.

- **Rule ID**: `SV-222518r960963_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000381`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Underlying host/AD access controls, user identity and software protection are accepted under the compliance assumption. CRAFT-specific authorization still requires an approved caller/mode policy, installed launcher group/mode, CA enrollment-agent/template/recipient restrictions and narrow msDS-KeyCredentialLink delegation. A fully compliant domain is not evidence that this particular service identity has only the intended recipient/attribute authority. Home PEM credentials also take priority over the configured privileged mechanism.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/config.hpp](../source/src/config.hpp): parse_config; [source/README.md](../source/README.md). Follow-up: Record permitted callers/modes/recipients; verify launcher permissions and effective CA/AD delegation using allowed/denied recipients. Keep privileged AD accounts outside the approved scope unless separately authorized. Add mode gating only if the approved policy requires it.

#### [V-222532] APSC-DV-001640 - The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoW policy or by the data owner.

- **Rule ID**: `SV-222532r1263559_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000778`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Enrollment Agent supports either Negotiate or mutual TLS for CES. Verified server TLS plus Kerberos client authentication is not the same as TLS client-certificate authentication. Device non-repudiation and non-releasable-data requirements, the selected CES mode and endpoint configuration are not established for a deployment.
- **Comments / Evidence**: Evidence: [source/src/config.hpp](../source/src/config.hpp): parse_config; [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/README.md](../source/README.md). Follow-up: Determine whether the applicable service/device profile requires mutual TLS; inspect client/server certificate configuration and test it when required. Confirm scope for modes that do not consume CES.

#### [V-222534] APSC-DV-001660 - Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.

- **Rule ID**: `SV-222534r961506_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001967`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Enrollment Agent supports either Negotiate or mutual TLS for CES. Verified server TLS plus Kerberos client authentication is not the same as TLS client-certificate authentication. Device non-repudiation and non-releasable-data requirements, the selected CES mode and endpoint configuration are not established for a deployment.
- **Comments / Evidence**: Evidence: [source/src/config.hpp](../source/src/config.hpp): parse_config; [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/README.md](../source/README.md). Follow-up: Determine whether the applicable service/device profile requires mutual TLS; inspect client/server certificate configuration and test it when required. Confirm scope for modes that do not consume CES.

#### [V-222550] APSC-DV-001810 - The application, when utilizing PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

- **Rule ID**: `SV-222550r961038_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000185`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Enrollment Agent and BYOC validate the user/agent chain with configured CA trust and CRL_CHECK/CRL_CHECK_ALL. All modes check that KDC trust/CRL files are safe and supply KDC anchors, but effective KDC CRL/hostname/EKU enforcement depends on administrator-controlled Kerberos configuration and the installed PKINIT plugin. Key Trust deliberately uses directory key authorization rather than a trusted user-CA chain, and adds its ephemeral issuer to the PKINIT anchor bundle. No blanket all-mode PKI-chain/revocation assurance follows from source alone.
- **Comments / Evidence**: Evidence: [source/src/x509.hpp](../source/src/x509.hpp): verify_chain, validate_leaf; [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt; [source/src/worker.cpp](../source/src/worker.cpp); [source/config/krb5.conf.example](../source/config/krb5.conf.example). Follow-up: Inspect effective Kerberos configuration/trust files and test revoked, expired, untrusted and missing-CRL cases against the actual plugin. Document the Key Trust authorization model and accepted trust anchors separately.

#### [V-222553] APSC-DV-001840 - The application, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

- **Rule ID**: `SV-222553r1015707_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004068`, `CCI-001991`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Enrollment Agent and BYOC validate the user/agent chain with configured CA trust and CRL_CHECK/CRL_CHECK_ALL. All modes check that KDC trust/CRL files are safe and supply KDC anchors, but effective KDC CRL/hostname/EKU enforcement depends on administrator-controlled Kerberos configuration and the installed PKINIT plugin. Key Trust deliberately uses directory key authorization rather than a trusted user-CA chain, and adds its ephemeral issuer to the PKINIT anchor bundle. No blanket all-mode PKI-chain/revocation assurance follows from source alone.
- **Comments / Evidence**: Evidence: [source/src/x509.hpp](../source/src/x509.hpp): verify_chain, validate_leaf; [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt; [source/src/worker.cpp](../source/src/worker.cpp); [source/config/krb5.conf.example](../source/config/krb5.conf.example). Follow-up: Inspect effective Kerberos configuration/trust files and test revoked, expired, untrusted and missing-CRL cases against the actual plugin. Document the Key Trust authorization model and accepted trust anchors separately.

#### [V-222567] APSC-DV-001995 - The application must not be vulnerable to race conditions.

- **Rule ID**: `SV-222567r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000366`, `CCI-003178`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository contains synthetic parser/cryptographic/filesystem tests, maintainer failure/race tests and validation notes. These are useful evidence, but they do not establish a current architecture-wide assessment covering this rule's required scan/review scope and all deployed modes/dependencies. Native CLI architecture does not exempt general input validation, XML processing or input-handling controls.
- **Comments / Evidence**: Evidence: [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md); [source/SECURITY.md](../source/SECURITY.md); [source/src/config.hpp](../source/src/config.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/x509.hpp](../source/src/x509.hpp). Follow-up: Supply current source/build-specific assessment settings, results and remediation/risk decisions for this rule. Include realistic malformed input, concurrency, termination and library/remote-error paths as applicable.

#### [V-222584] APSC-DV-002300 - The application must only allow the use of DoW-approved certificate authorities for verification of the establishment of protected sessions.

- **Rule ID**: `SV-222584r1263590_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002470`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Configured trust bundles limit certificate acceptance, but the code does not identify or enforce DoW-approved PKI/ECA issuer status. The Key Trust client identity is locally generated and directory-authorized; its ephemeral issuer is added to the PKINIT anchor bundle. Administrator-provisioned trust and a locally generated issuer are not evidence of approval under this control.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/x509.hpp](../source/src/x509.hpp): verify_chain; [source/src/directory.hpp](../source/src/directory.hpp): make_key_trust_pair; [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt. Follow-up: Review actual issuer inventories, approved trust policy and effective TLS/KDC anchors. Resolve Key Trust applicability/authorization explicitly; do not label every configured CA DoW approved.

#### [V-222585] APSC-DV-002310 - The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.

- **Rule ID**: `SV-222585r961122_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-001190`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Validation/acquisition failures normally preserve the existing cache and block publication. Key Trust uses an independent guardian and requires successful removal before returning credential bytes, but directory unavailability or host failure can leave a residual key. Cleanup failure records identify the directory object when logging is possible; they do not guarantee a durable record or successful cleanup on every abort. Recovery information and all failure-mode test results are not established.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/directory.hpp](../source/src/directory.hpp): KeyCredentialGuard, detach_key_credential; [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Test initialization, publication, signal/kill, host and directory failures across enabled modes. Define retained recovery evidence and an approved residual-key detection/removal procedure.

#### [V-222594] APSC-DV-002400 - The application must restrict the ability to launch Denial of Service (DoS) attacks against itself or other information systems.

- **Rule ID**: `SV-222594r961152_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001094`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Implemented limits include bounded input/response sizes, worker CPU/address-space/deadline limits, network timeouts, privileged-mode per-user acquisition rate limiting and maintainer retry backoff. Home-mode acquisition is not subject to the privileged issuance rate limiter, and there is no global issuance quota. No complete deployed load/DoS test and accepted residual-risk record is supplied.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): read_all; [source/src/unprivileged.hpp](../source/src/unprivileged.hpp): rate_limit; [source/src/enroll.hpp](../source/src/enroll.hpp): receive, send_ces; [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Test multi-user/concurrent acquisition, malformed input and service outages against realistic resource and CA/DC capacity limits; document remaining risks and approved mitigations.

#### [V-222605] APSC-DV-002520 - The application must protect from canonical representation vulnerabilities.

- **Rule ID**: `SV-222605r961158_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001310`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository contains synthetic parser/cryptographic/filesystem tests, maintainer failure/race tests and validation notes. These are useful evidence, but they do not establish a current architecture-wide assessment covering this rule's required scan/review scope and all deployed modes/dependencies. Native CLI architecture does not exempt general input validation, XML processing or input-handling controls.
- **Comments / Evidence**: Evidence: [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md); [source/SECURITY.md](../source/SECURITY.md); [source/src/config.hpp](../source/src/config.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/x509.hpp](../source/src/x509.hpp). Follow-up: Supply current source/build-specific assessment settings, results and remediation/risk decisions for this rule. Include realistic malformed input, concurrency, termination and library/remote-error paths as applicable.

#### [V-222606] APSC-DV-002530 - The application must validate all input.

- **Rule ID**: `SV-222606r961158_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001310`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository contains synthetic parser/cryptographic/filesystem tests, maintainer failure/race tests and validation notes. These are useful evidence, but they do not establish a current architecture-wide assessment covering this rule's required scan/review scope and all deployed modes/dependencies. Native CLI architecture does not exempt general input validation, XML processing or input-handling controls.
- **Comments / Evidence**: Evidence: [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md); [source/SECURITY.md](../source/SECURITY.md); [source/src/config.hpp](../source/src/config.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/x509.hpp](../source/src/x509.hpp). Follow-up: Supply current source/build-specific assessment settings, results and remediation/risk decisions for this rule. Include realistic malformed input, concurrency, termination and library/remote-error paths as applicable.

#### [V-222608] APSC-DV-002550 - The application must not be vulnerable to XML-oriented attacks.

- **Rule ID**: `SV-222608r961158_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-001310`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository contains synthetic parser/cryptographic/filesystem tests, maintainer failure/race tests and validation notes. These are useful evidence, but they do not establish a current architecture-wide assessment covering this rule's required scan/review scope and all deployed modes/dependencies. Native CLI architecture does not exempt general input validation, XML processing or input-handling controls.
- **Comments / Evidence**: Evidence: [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md); [source/SECURITY.md](../source/SECURITY.md); [source/src/config.hpp](../source/src/config.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/x509.hpp](../source/src/x509.hpp). Follow-up: Supply current source/build-specific assessment settings, results and remediation/risk decisions for this rule. Include realistic malformed input, concurrency, termination and library/remote-error paths as applicable.

#### [V-222609] APSC-DV-002560 - The application must not be subject to input handling vulnerabilities.

- **Rule ID**: `SV-222609r961656_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-002754`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository contains synthetic parser/cryptographic/filesystem tests, maintainer failure/race tests and validation notes. These are useful evidence, but they do not establish a current architecture-wide assessment covering this rule's required scan/review scope and all deployed modes/dependencies. Native CLI architecture does not exempt general input validation, XML processing or input-handling controls.
- **Comments / Evidence**: Evidence: [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md); [source/SECURITY.md](../source/SECURITY.md); [source/src/config.hpp](../source/src/config.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/x509.hpp](../source/src/x509.hpp). Follow-up: Supply current source/build-specific assessment settings, results and remediation/risk decisions for this rule. Include realistic malformed input, concurrency, termination and library/remote-error paths as applicable.

#### [V-222612] APSC-DV-002590 - The application must not be vulnerable to overflow attacks.

- **Rule ID**: `SV-222612r961665_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-002824`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository contains synthetic parser/cryptographic/filesystem tests, maintainer failure/race tests and validation notes. These are useful evidence, but they do not establish a current architecture-wide assessment covering this rule's required scan/review scope and all deployed modes/dependencies. Native CLI architecture does not exempt general input validation, XML processing or input-handling controls.
- **Comments / Evidence**: Evidence: [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md); [source/SECURITY.md](../source/SECURITY.md); [source/src/config.hpp](../source/src/config.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/x509.hpp](../source/src/x509.hpp). Follow-up: Supply current source/build-specific assessment settings, results and remediation/risk decisions for this rule. Include realistic malformed input, concurrency, termination and library/remote-error paths as applicable.

#### [V-222630] APSC-DV-002995 - The Configuration Management (CM) repository must be properly patched and STIG compliant.

- **Rule ID**: `SV-222630r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001795`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Source/configuration are present in a Git repository, but the checkout does not establish repository host STIG/patch status, quarterly access reviews, an approved SCM plan or a Configuration Control Board. No branch-protection, mandatory peer-review or signed-commit policy is inferred from using Git.
- **Comments / Evidence**: Evidence: [README.md](../README.md); [source/README.md](../source/README.md); [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Provide the organization's CM environment assessment, access-review records, complete SCM plan and release-cycle CCB records against this rule. Development-process controls remain in scope for this source project.

#### [V-222631] APSC-DV-003000 - Access privileges to the Configuration Management (CM) repository must be reviewed every three months.

- **Rule ID**: `SV-222631r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001795`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Source/configuration are present in a Git repository, but the checkout does not establish repository host STIG/patch status, quarterly access reviews, an approved SCM plan or a Configuration Control Board. No branch-protection, mandatory peer-review or signed-commit policy is inferred from using Git.
- **Comments / Evidence**: Evidence: [README.md](../README.md); [source/README.md](../source/README.md); [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Provide the organization's CM environment assessment, access-review records, complete SCM plan and release-cycle CCB records against this rule. Development-process controls remain in scope for this source project.

#### [V-222632] APSC-DV-003010 - A Software Configuration Management (SCM) plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization must be created and maintained.

- **Rule ID**: `SV-222632r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001795`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Source/configuration are present in a Git repository, but the checkout does not establish repository host STIG/patch status, quarterly access reviews, an approved SCM plan or a Configuration Control Board. No branch-protection, mandatory peer-review or signed-commit policy is inferred from using Git.
- **Comments / Evidence**: Evidence: [README.md](../README.md); [source/README.md](../source/README.md); [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Provide the organization's CM environment assessment, access-review records, complete SCM plan and release-cycle CCB records against this rule. Development-process controls remain in scope for this source project.

#### [V-222633] APSC-DV-003020 - A Configuration Control Board (CCB) that meets at least every release cycle, for managing the Configuration Management (CM) process must be established.

- **Rule ID**: `SV-222633r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001795`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Source/configuration are present in a Git repository, but the checkout does not establish repository host STIG/patch status, quarterly access reviews, an approved SCM plan or a Configuration Control Board. No branch-protection, mandatory peer-review or signed-commit policy is inferred from using Git.
- **Comments / Evidence**: Evidence: [README.md](../README.md); [source/README.md](../source/README.md); [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Provide the organization's CM environment assessment, access-review records, complete SCM plan and release-cycle CCB records against this rule. Development-process controls remain in scope for this source project.

#### [V-222635] APSC-DV-003040 - The application must not be hosted on a general purpose machine if the application is designated as critical or high availability by the ISSO.

- **Rule ID**: `SV-222635r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002828`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The ISSO's criticality/high-availability designation and deployment topology are not established. CRAFT is a client, while availability of its host, CA/CES, directory and KDC still affects the workflow. A small or stateless-looking utility does not establish an availability exemption.
- **Comments / Evidence**: Evidence: [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Obtain the availability designation; inspect required redundancy, host separation and dependent-service architecture.

#### [V-222643] APSC-DV-003120 - The application must have the capability to mark sensitive/classified output when required.

- **Rule ID**: `SV-222643r1263526_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-001010`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository does not establish the deployed data classification or whether credentials, identity data and diagnostics require security markings. Binary output and the absence of a web UI do not establish the STIG marking exemption. CRAFT does not supply a classification-marking facility.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Obtain the information owner's classification and marking requirements. Use the benchmark's Not Applicable criteria only when the absence of classified/CUI or other marking requirements is established; otherwise demonstrate required markings.

#### [V-222644] APSC-DV-003130 - Prior to each release of the application, updates to system, or applying patches; tests plans and procedures must be created and executed.

- **Rule ID**: `SV-222644r961863_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-003004`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: TESTING.md provides build/acceptance procedures and some validation records. It does not establish executed plans for every release/system update/patch or an approved annual initialization/shutdown/abort test record for the complete deployed system. Existing synthetic failure tests do not substitute for all installed privilege and remote-service failure cases.
- **Comments / Evidence**: Evidence: [source/TESTING.md](../source/TESTING.md); [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp). Follow-up: Provide source/build/deployment-specific test plans, actual run results and the required per-release or annual review records.

#### [V-222646] APSC-DV-003150 - At least one tester must be designated to test for security flaws in addition to functional testing.

- **Rule ID**: `SV-222646r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003182`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Test code and validation notes exist, but they do not identify an assigned tester responsible for security-flaw testing in addition to functional testing.
- **Comments / Evidence**: Evidence: [source/TESTING.md](../source/TESTING.md); [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp). Follow-up: Provide the security tester designation, responsibilities and evidence of the required security testing.

#### [V-222647] APSC-DV-003160 - Test procedures must be created and at least annually executed to ensure system initialization, shutdown, and aborts are configured to verify the system remains in a secure state.

- **Rule ID**: `SV-222647r961863_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-003182`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: TESTING.md provides build/acceptance procedures and some validation records. It does not establish executed plans for every release/system update/patch or an approved annual initialization/shutdown/abort test record for the complete deployed system. Existing synthetic failure tests do not substitute for all installed privilege and remote-service failure cases.
- **Comments / Evidence**: Evidence: [source/TESTING.md](../source/TESTING.md); [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp). Follow-up: Provide source/build/deployment-specific test plans, actual run results and the required per-release or annual review records.

#### [V-222648] APSC-DV-003170 - An application code review must be performed on the application.

- **Rule ID**: `SV-222648r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003187`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Security notes and this control-focused source review provide useful review evidence, but do not establish the organization's complete code-review process or a current report covering all security flaw classes listed in the check. An ASD disposition table is not an exhaustive security code audit.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/TESTING.md](../source/TESTING.md); [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp). Follow-up: Provide the code-review procedure and current manual/tool reports with scope, findings and remediation for format strings, leaks, overflows, races, input handling and other applicable classes.

#### [V-222649] APSC-DV-003180 - Code coverage statistics must be maintained for each release of the application.

- **Rule ID**: `SV-222649r961863_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-003188`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The number of passing checks is not code coverage. No per-release coverage report establishing statement/branch/path coverage and uncovered areas was supplied by the checkout.
- **Comments / Evidence**: Evidence: [source/CMakeLists.txt](../source/CMakeLists.txt); [source/TESTING.md](../source/TESTING.md); [source/tests/tests.cpp](../source/tests/tests.cpp). Follow-up: Provide maintained release-specific coverage statistics and the associated instrumented build/test results.

#### [V-222650] APSC-DV-003190 - Flaws found during a code review must be tracked in a defect tracking system.

- **Rule ID**: `SV-222650r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003161`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Version control and security guidance do not demonstrate that review flaws are entered into an approved defect tracker/project plan or that each change receives an IA/accreditation impact assessment before implementation. External process records were not reviewed.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/TESTING.md](../source/TESTING.md); [README.md](../README.md). Follow-up: Provide traceable flaw/change records, risk/impact decisions, remediation commitments and the approved project planning process.

#### [V-222651] APSC-DV-003200 - The changes to the application must be assessed for IA and accreditation impact prior to implementation.

- **Rule ID**: `SV-222651r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003173`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Version control and security guidance do not demonstrate that review flaws are entered into an approved defect tracker/project plan or that each change receives an IA/accreditation impact assessment before implementation. External process records were not reviewed.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/TESTING.md](../source/TESTING.md); [README.md](../README.md). Follow-up: Provide traceable flaw/change records, risk/impact decisions, remediation commitments and the approved project planning process.

#### [V-222652] APSC-DV-003210 - Security flaws must be fixed or addressed in the project plan.

- **Rule ID**: `SV-222652r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003178`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Version control and security guidance do not demonstrate that review flaws are entered into an approved defect tracker/project plan or that each change receives an IA/accreditation impact assessment before implementation. External process records were not reviewed.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/TESTING.md](../source/TESTING.md); [README.md](../README.md). Follow-up: Provide traceable flaw/change records, risk/impact decisions, remediation commitments and the approved project planning process.

#### [V-222653] APSC-DV-003215 - The application development team must follow a set of coding standards.

- **Rule ID**: `SV-222653r961863_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-003233`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository supplies formatting rules in source/.clang-format and C++20 build/warning/hardening settings. Developer awareness and adherence to the agreed coding standard were not independently established by this review. The build uses Werror=format-security, not a blanket Werror requirement.
- **Comments / Evidence**: Evidence: [source/.clang-format](../source/.clang-format); [source/CMakeLists.txt](../source/CMakeLists.txt); [source/src/common.hpp](../source/src/common.hpp); [source/README.md](../source/README.md). Follow-up: Confirm the coding-standard scope and developer/review evidence; do not infer an all-warning error policy.

#### [V-222654] APSC-DV-003220 - The designer must create and update the Design Document for each release of the application.

- **Rule ID**: `SV-222654r961863_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-003233`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Process/setup guides and SECURITY.md describe interfaces, privileges, threats, countermeasures and limitations. They do not establish the full deployment data-protection/restoration requirements, release-by-release design/threat-model review, selected risk analysis or ISSO/ISSM approval required by these checks.
- **Comments / Evidence**: Evidence: [docs/01-CRAFT-Process-Overview.pdf](01-CRAFT-Process-Overview.pdf); [docs/02-CRAFT-Configuration-and-Validation.pdf](02-CRAFT-Configuration-and-Validation.pdf); [docs/03-Enrollment-Agent-Restrictions.md](03-Enrollment-Agent-Restrictions.md); [docs/04-Key-Credential-Link-Delegation.md](04-Key-Credential-Link-Delegation.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Complete the required design/threat-model content and provide release review and risk-approval records.

#### [V-222655] APSC-DV-003230 - Threat models must be documented and reviewed for each application release and updated as required by design and functionality changes or when new threats are discovered.

- **Rule ID**: `SV-222655r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003256`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Process/setup guides and SECURITY.md describe interfaces, privileges, threats, countermeasures and limitations. They do not establish the full deployment data-protection/restoration requirements, release-by-release design/threat-model review, selected risk analysis or ISSO/ISSM approval required by these checks.
- **Comments / Evidence**: Evidence: [docs/01-CRAFT-Process-Overview.pdf](01-CRAFT-Process-Overview.pdf); [docs/02-CRAFT-Configuration-and-Validation.pdf](02-CRAFT-Configuration-and-Validation.pdf); [docs/03-Enrollment-Agent-Restrictions.md](03-Enrollment-Agent-Restrictions.md); [docs/04-Key-Credential-Link-Delegation.md](04-Key-Credential-Link-Delegation.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Complete the required design/threat-model content and provide release review and risk-approval records.

#### [V-222656] APSC-DV-003235 - The application must not be subject to error handling vulnerabilities.

- **Rule ID**: `SV-222656r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003272`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The repository contains synthetic parser/cryptographic/filesystem tests, maintainer failure/race tests and validation notes. These are useful evidence, but they do not establish a current architecture-wide assessment covering this rule's required scan/review scope and all deployed modes/dependencies. Native CLI architecture does not exempt general input validation, XML processing or input-handling controls.
- **Comments / Evidence**: Evidence: [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md); [source/SECURITY.md](../source/SECURITY.md); [source/src/config.hpp](../source/src/config.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/x509.hpp](../source/src/x509.hpp). Follow-up: Supply current source/build-specific assessment settings, results and remediation/risk decisions for this rule. Include realistic malformed input, concurrency, termination and library/remote-error paths as applicable.

#### [V-222657] APSC-DV-003236 - The application development team must provide an application incident response plan.

- **Rule ID**: `SV-222657r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003289`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: SECURITY.md contains operational disable/credential-response guidance. That is not evidence of a development incident-response process that tracks and confirms reported bugs/vulnerabilities, tracks remediation and notifies users of available fixes.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md): Immediate Disable; [source/TESTING.md](../source/TESTING.md). Follow-up: Provide the development incident-response plan, reporting/triage channel, tracking/confirmation workflow and implemented update-notification process with records.

#### [V-222659] APSC-DV-003250 - The application must be decommissioned when maintenance or support is no longer available.

- **Rule ID**: `SV-222659r961863_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-003376`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: OS/domain patches, vendor support and distribution-managed dependencies are covered by the platform assumption. CRAFT itself is locally built/installed; its release-update checks, superseded-build removal, maintenance responsibility and decommission/user-notification process are not established merely by a compliant OS package inventory.
- **Comments / Evidence**: Evidence: [README.md](../README.md): Project status; [source/README.md](../source/README.md); [source/CMakeLists.txt](../source/CMakeLists.txt); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Assign an application maintainer; document weekly release/security review, supported builds, replacement/removal and decommission notifications. Use the existing OS package/update mechanism for CRAFT where practical, with a verified release artifact.

#### [V-222660] APSC-DV-003260 - Procedures must be in place to notify users when an application is decommissioned.

- **Rule ID**: `SV-222660r961863_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-003374`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: OS/domain patches, vendor support and distribution-managed dependencies are covered by the platform assumption. CRAFT itself is locally built/installed; its release-update checks, superseded-build removal, maintenance responsibility and decommission/user-notification process are not established merely by a compliant OS package inventory.
- **Comments / Evidence**: Evidence: [README.md](../README.md): Project status; [source/README.md](../source/README.md); [source/CMakeLists.txt](../source/CMakeLists.txt); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Assign an application maintainer; document weekly release/security review, supported builds, replacement/removal and decommission notifications. Use the existing OS package/update mechanism for CRAFT where practical, with a verified release artifact.

#### [V-222664] APSC-DV-003290 - If the application contains classified data, a Security Classification Guide must exist containing data elements and their classification.

- **Rule ID**: `SV-222664r1051277_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003124`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The source review does not establish whether the deployment processes classified information or SAMI. Ordinary OpenSSL/Kerberos cryptography does not demonstrate NSA Type 1 or other required classified-data protections, and the repository supplies no deployment Security Classification Guide.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/README.md](../source/README.md); [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Obtain the classification/network designation. Use Not Applicable only for a documented nonclassified scope; otherwise review the required classification guide and approved cryptographic protections.

#### [V-222669] APSC-DV-003340 - At least one application administrator must be registered to receive update notifications, or security alerts, when automated alerts are available.

- **Rule ID**: `SV-222669r961863_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-001285`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The checkout does not establish administrator subscription to security/update alerts or an implemented project notification process that supplies issue/risk details, patch availability, acquisition instructions and interim mitigations. Repository availability alone is not update-notification evidence.
- **Comments / Evidence**: Evidence: [README.md](../README.md); [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Provide the administrator subscriptions and maintained notification process with representative advisory/update records.

#### [V-222670] APSC-DV-003345 - The application must provide notifications or alerts when product update and security related patches are available.

- **Rule ID**: `SV-222670r961863_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-001286`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The checkout does not establish administrator subscription to security/update alerts or an implemented project notification process that supplies issue/risk details, patch availability, acquisition instructions and interim mitigations. Repository availability alone is not update-notification evidence.
- **Comments / Evidence**: Evidence: [README.md](../README.md); [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Provide the administrator subscriptions and maintained notification process with representative advisory/update records.

#### [V-222673] APSC-DV-003400 - The Program Manager must verify all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.

- **Rule ID**: `SV-222673r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002052`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: Source code, tests and coding style do not establish annual job-specific security/SDLC training for program management, designers, developers and testers. No personnel training records were reviewed.
- **Comments / Evidence**: Evidence: [README.md](../README.md); [source/TESTING.md](../source/TESTING.md). Follow-up: Provide the annual role-specific training program and completion records required by the check.

#### [V-265634] APSC-DV-002010 - The application must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

- **Rule ID**: `SV-265634r1117183_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002450`
- **Evaluation Status**: **`Not_Reviewed`**
- **Finding Details / Assessment**: The source review does not establish whether the deployment processes classified information or SAMI. Ordinary OpenSSL/Kerberos cryptography does not demonstrate NSA Type 1 or other required classified-data protections, and the repository supplies no deployment Security Classification Guide.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/README.md](../source/README.md); [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Obtain the classification/network designation. Use Not Applicable only for a documented nonclassified scope; otherwise review the required classification guide and approved cryptographic protections.

### 5.3. Source behavior or inherited controls supported (109 controls)

#### [V-222396] APSC-DV-000160 - The application must implement DoW-approved encryption to protect the confidentiality of remote access sessions.

- **Rule ID**: `SV-222396r1263527_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000068`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT offers no remote-access session; remote access to the host it runs on is the OS's. Its own outbound connections are protected by OS-provided mechanisms: TLS 1.2 or later to CES, and Kerberos with a GSSAPI security layer of at least SSF 128 to the directory, which Active Directory requires in place of TLS for a GSSAPI bind.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/directory.hpp](../source/src/directory.hpp): ldap_connect. Follow-up: The check text names TLS; an assessor who reads it as covering CRAFT's directory connection must accept the GSSAPI security layer as the equivalent.

#### [V-222397] APSC-DV-000170 - The application must implement cryptographic mechanisms to protect the integrity of remote access sessions.

- **Rule ID**: `SV-222397r1263528_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001453`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT offers no remote-access session; remote access to the host it runs on is the OS's. Its own outbound connections are protected by OS-provided mechanisms: TLS 1.2 or later to CES, and Kerberos with a GSSAPI security layer of at least SSF 128 to the directory, which Active Directory requires in place of TLS for a GSSAPI bind.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/directory.hpp](../source/src/directory.hpp): ldap_connect. Follow-up: The check text names TLS; an assessor who reads it as covering CRAFT's directory connection must accept the GSSAPI security layer as the equivalent.

#### [V-222407] APSC-DV-000280 - The application must provide automated mechanisms for supporting account management functions.

- **Rule ID**: `SV-222407r1043176_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000015`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Automated host/enterprise account lifecycle management is provided by the compliant identity infrastructure. CRAFT only resolves an existing real UID and AD identity; it does not create an alternate user-management workflow.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-411040, RHEL-09-411050; host/AD account lifecycle controls; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Keep caller provisioning and removal in the inherited identity process. CRAFT-specific group membership and delegation remain subject to the authorization review items.

#### [V-222409] APSC-DV-000300 - The application must automatically remove or disable temporary user accounts 72 hours after account creation.

- **Rule ID**: `SV-222409r1263529_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000016`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Temporary host/enterprise accounts, when authorized, are expired by the inherited identity system within the required 72 hours. CRAFT creates no temporary user account. Its temporary certificates and msDS-KeyCredentialLink values are authenticators, assessed separately from account expiration.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-411040; enterprise temporary-account controls; [source/src/worker.cpp](../source/src/worker.cpp); [source/src/directory.hpp](../source/src/directory.hpp); [source/README.md](../source/README.md). Follow-up: Maintain enterprise temporary-account expiry. Key Trust credential cleanup is a separate application obligation.

#### [V-222410] APSC-DV-000310 - The application must have a process, feature or function that prevents removal or disabling of emergency accounts. 

- **Rule ID**: `SV-222410r961863_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000366`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT has no accounts. Any emergency accounts are host or directory accounts, protected against removal by the platform that holds them.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account. Follow-up: None for CRAFT.

#### [V-222412] APSC-DV-000330 - Unnecessary application accounts must be disabled, or deleted.

- **Rule ID**: `SV-222412r960774_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000017`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Necessary/noninteractive service accounts and authorized user accounts are governed by the compliant host/AD account inventory and removal/disablement process. CRAFT has no additional built-in password or independent application account database. The documented craft account is required only for privileged modes; source does not create a hidden account bypass.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Host/AD account inventory, inactive-account and service-account restrictions; RHEL-09-411050; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Keep the deployed account inventory within the inherited account-management process. The exact CRAFT CA recipient scope and Key Trust delegation are separate configuration decisions.

#### [V-222425] APSC-DV-000460 - The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

- **Rule ID**: `SV-222425r1263530_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000213`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the platform mechanisms that enforce it. Who may run the privileged launcher is host access control: the craft-users group on a mode-04750 launcher. Service secrets are readable only by root and the unprivileged craft service account. What the service identity may do is set by AD CS enrollment-agent restrictions and by the directory delegation on msDS-KeyCredentialLink. CRAFT adds no authorization store of its own, runs its worker without root and drops privilege permanently before it handles credentials.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/common.hpp](../source/src/common.hpp): drop, root_open; [source/README.md](../source/README.md): Shared privileged installation; [scripts/Configure-CRAFT-CA.ps1](../scripts/Configure-CRAFT-CA.ps1): Assert-CAEnrollmentPolicy; [scripts/Grant-CRAFTKeyCredentialLink.ps1](../scripts/Grant-CRAFTKeyCredentialLink.ps1); [source/TESTING.md](../source/TESTING.md): Multi-OS Validation. Follow-up: Keep the launcher group, CA restrictions and delegation scope in the host and AD configuration baselines.

#### [V-222426] APSC-DV-000470 - The application must enforce organization-defined discretionary access control policies over defined subjects and objects.

- **Rule ID**: `SV-222426r1263531_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002165`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: root_open rejects non-root-owned or group/world-writable administrator-controlled path components and unsafe file types. Caller-home and private-file checks enforce caller ownership and restricted writes. Ordinary caller data cannot supply alternate system configuration or trust paths. These are implemented DAC and configuration write-protection mechanisms.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): root_open, caller_home, open_private; [source/src/config.hpp](../source/src/config.hpp): config; [source/src/x509.hpp](../source/src/x509.hpp): user_identity_files. Follow-up: Maintain the documented installation permissions and verify the effective deployed access policy.

#### [V-222429] APSC-DV-000500 - The application must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

- **Rule ID**: `SV-222429r961353_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002235`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the platform mechanisms that enforce it. Who may run the privileged launcher is host access control: the craft-users group on a mode-04750 launcher. Service secrets are readable only by root and the unprivileged craft service account. What the service identity may do is set by AD CS enrollment-agent restrictions and by the directory delegation on msDS-KeyCredentialLink. CRAFT adds no authorization store of its own, runs its worker without root and drops privilege permanently before it handles credentials.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/common.hpp](../source/src/common.hpp): drop, root_open; [source/README.md](../source/README.md): Shared privileged installation; [scripts/Configure-CRAFT-CA.ps1](../scripts/Configure-CRAFT-CA.ps1): Assert-CAEnrollmentPolicy; [scripts/Grant-CRAFTKeyCredentialLink.ps1](../scripts/Grant-CRAFTKeyCredentialLink.ps1); [source/TESTING.md](../source/TESTING.md): Multi-OS Validation. Follow-up: Keep the launcher group, CA restrictions and delegation scope in the host and AD configuration baselines.

#### [V-222430] APSC-DV-000510 - The application must execute without excessive account permissions.

- **Rule ID**: `SV-222430r961359_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-002233`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the platform mechanisms that enforce it. Who may run the privileged launcher is host access control: the craft-users group on a mode-04750 launcher. Service secrets are readable only by root and the unprivileged craft service account. What the service identity may do is set by AD CS enrollment-agent restrictions and by the directory delegation on msDS-KeyCredentialLink. CRAFT adds no authorization store of its own, runs its worker without root and drops privilege permanently before it handles credentials.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/common.hpp](../source/src/common.hpp): drop, root_open; [source/README.md](../source/README.md): Shared privileged installation; [scripts/Configure-CRAFT-CA.ps1](../scripts/Configure-CRAFT-CA.ps1): Assert-CAEnrollmentPolicy; [scripts/Grant-CRAFTKeyCredentialLink.ps1](../scripts/Grant-CRAFTKeyCredentialLink.ps1); [source/TESTING.md](../source/TESTING.md): Multi-OS Validation. Follow-up: Keep the launcher group, CA restrictions and delegation scope in the host and AD configuration baselines.

#### [V-222431] APSC-DV-000520 - The application must audit the execution of privileged functions.

- **Rule ID**: `SV-222431r961362_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002234`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Privileged launcher execution and OS-level access are audited by the host with invoking identity, executable and syscall outcome. CRAFT also emits worker acquisition results. The absence of duplicate application messages for the same privileged executable invocation is not a finding when the inherited host audit trail supplies the required execution record. This does not close the separate findings for specific object accesses, directory-key changes or final application publication outcome.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-654010; RHEL-09-653100; host privileged-execution auditing; [source/src/launcher.cpp](../source/src/launcher.cpp): main, run_worker; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/src/common.hpp](../source/src/common.hpp): audit. Follow-up: Preserve host privileged-execution coverage when installing the launcher. CRAFT's own records (source commit c107bef) supply the semantics that host/AD records do not.

#### [V-222432] APSC-DV-000530 - The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.

- **Rule ID**: `SV-222432r960840_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000044`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the OS and Active Directory. CRAFT has no logon and offers no authenticator a user could guess: it never prompts for a password or PIN. Invalid logon attempts, lockout and the approved unlock process are those of the host session and the directory account.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (authentication inherited from OS logon); [source/src/pkinit.hpp](../source/src/pkinit.hpp): refuse_prompt; [source/src/unprivileged.hpp](../source/src/unprivileged.hpp): rate_limit. Follow-up: None for CRAFT; the host and AD lockout policy and unlock procedure apply.

#### [V-222433] APSC-DV-000540 - The application administrator must follow an approved process to unlock locked user accounts.

- **Rule ID**: `SV-222433r961368_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002238`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the OS and Active Directory. CRAFT has no logon and offers no authenticator a user could guess: it never prompts for a password or PIN. Invalid logon attempts, lockout and the approved unlock process are those of the host session and the directory account.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (authentication inherited from OS logon); [source/src/pkinit.hpp](../source/src/pkinit.hpp): refuse_prompt; [source/src/unprivileged.hpp](../source/src/unprivileged.hpp): rate_limit. Follow-up: None for CRAFT; the host and AD lockout policy and unlock procedure apply.

#### [V-222438] APSC-DV-000590 - The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.

- **Rule ID**: `SV-222438r1263542_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000166`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Non-repudiation rests on audit records, deferred to the OS by the system owner's determination. CRAFT's records bind each request, issuance, Key Trust change and publication to the caller's UID and account name, and the host audit service binds that session to its login identity. CRAFT offers no other action a caller could later deny.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: None beyond the inherited audit retention.

#### [V-222446] APSC-DV-000670 - The application must record a time stamp indicating when the event occurred.

- **Rule ID**: `SV-222446r960879_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000169`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Audit event timestamping, system-clock synchronization and UTC/GMT mapping are supplied by the compliant host/AD audit infrastructure. CRAFT already uses that OS logging path and POSIX clock; it does not implement a conflicting application time source.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Host/AD audit timestamp and authoritative time-source controls; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Maintain the inherited time source and preserve timestamp/timezone fields in forwarded events.

#### [V-222449] APSC-DV-000700 - The application must record the username or user ID of the user associated with the event.

- **Rule ID**: `SV-222449r960879_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000169`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Host-generated event identity supplies UID/AUID and process identity for the host audit trail. Emitted CRAFT records carry LOG_PID, and worker acquisition records additionally carry requesting_uid. The compliant host logging/auditing context identifies the account associated with an event even where a maintainer message omits a redundant UID in its text. Service-account origin must not be misrepresented as the original caller; explicit requesting_uid in guardian events remains a useful application correlation improvement.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-653100, RHEL-09-654270; trusted host UID/AUID and process metadata; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/src/maintain.hpp](../source/src/maintain.hpp): serve; [source/src/directory.hpp](../source/src/directory.hpp): detach_key_credential, KeyCredentialGuard. Follow-up: Preserve trusted origin identity in collection/forwarding. Include requesting_uid and a request identifier in added application events to distinguish caller identity from service/guardian identity.

#### [V-222451] APSC-DV-000720 - The application must generate audit records when successful/unsuccessful attempts to access security objects occur.

- **Rule ID**: `SV-222451r961791_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Closed by CRAFT's own records together with the host audit and logging services, to which logging is deferred by the system owner's determination. CRAFT records each request, issuance and failure, with the caller's UID and a request number, in the host AUTHPRIV log, and refuses to act when that service does not take a record. Reads of CRAFT's keys, keytab, configuration and trust files are host file accesses, recorded with the login identity by the STIG-compliant host audit service; source/config/craft.audit.rules supplies the watches. Access to the directory attribute is recorded by Active Directory auditing.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): audit, report; [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/config/craft.audit.rules](../source/config/craft.audit.rules); [source/README.md](../source/README.md): Audit Records and Diagnostics; [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Carry the example watches, or equivalent ones, in the host audit configuration and keep the msDS-KeyCredentialLink SACL in the Active Directory audit policy. The rules file has not been loaded on a live host by this assessment.

#### [V-222455] APSC-DV-000760 - The application must generate audit records when successful/unsuccessful attempts to modify security objects occur.

- **Rule ID**: `SV-222455r961803_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: CRAFT changes two objects and records both. Each Key Trust change to msDS-KeyCredentialLink produces a key credential added or key credential removed record naming the directory object and the worker; a refused change produces a failure record and a value left behind a CRITICAL one. Each cache replacement produces a request finished record with outcome=published, and each maintainer renewal a renewed TGT record before the cache is replaced. A change whose record the host logging service does not take is withdrawn or not made. Changes to CRAFT's own files are host file modifications, recorded by the host audit service to which logging is deferred by the system owner's determination.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/directory.hpp](../source/src/directory.hpp): KeyCredentialGuard, detach_key_credential; [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/maintain.hpp](../source/src/maintain.hpp): renew; [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/tests.cpp](../source/tests/tests.cpp); [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Keep directory attribute-change auditing for msDS-KeyCredentialLink so that Active Directory records can be matched with CRAFT's.

#### [V-222462] APSC-DV-000830 - The application must generate audit records when successful/unsuccessful logon attempts occur.

- **Rule ID**: `SV-222462r961824_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. User authentication is performed by the host and the AD KDC, whose compliant authentication audit trail records actual successes/failures, including Kerberos TGT/preauthentication results such as 4768/4771. CRAFT has no independent application logon/session store and also emits its worker acquisition result. A local validation or cache-publication error is an operational/object event rather than a second failed KDC logon; those application semantics remain in the separate object/data-change and lifecycle findings.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Host/AD successful/failed authentication auditing; KDC events 4768/4771; [source/src/worker.cpp](../source/src/worker.cpp); [source/src/launcher.cpp](../source/src/launcher.cpp): main, run_worker; [source/src/worker.cpp](../source/src/worker.cpp): main. Follow-up: Preserve authoritative host/KDC authentication events. Include final invocation/publication outcomes in the application audit improvements without relabeling successful KDC authentication as a failed logon.

#### [V-222463] APSC-DV-000840 - The application must generate audit records for privileged activities or other system-level access.

- **Rule ID**: `SV-222463r961827_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Privileged launcher execution and OS-level access are audited by the host with invoking identity, executable and syscall outcome. CRAFT also emits worker acquisition results. The absence of duplicate application messages for the same privileged executable invocation is not a finding when the inherited host audit trail supplies the required execution record. This does not close the separate findings for specific object accesses, directory-key changes or final application publication outcome.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-654010; RHEL-09-653100; host privileged-execution auditing; [source/src/launcher.cpp](../source/src/launcher.cpp): main, run_worker; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/src/common.hpp](../source/src/common.hpp): audit. Follow-up: Preserve host privileged-execution coverage when installing the launcher. CRAFT's own records (source commit c107bef) supply the semantics that host/AD records do not.

#### [V-222465] APSC-DV-000860 - The application must generate audit records when successful/unsuccessful accesses to objects occur.

- **Rule ID**: `SV-222465r961836_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Closed by CRAFT's own records together with the host audit and logging services, to which logging is deferred by the system owner's determination. CRAFT records each request, issuance and failure, with the caller's UID and a request number, in the host AUTHPRIV log, and refuses to act when that service does not take a record. Reads of CRAFT's keys, keytab, configuration and trust files are host file accesses, recorded with the login identity by the STIG-compliant host audit service; source/config/craft.audit.rules supplies the watches. Access to the directory attribute is recorded by Active Directory auditing.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): audit, report; [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/config/craft.audit.rules](../source/config/craft.audit.rules); [source/README.md](../source/README.md): Audit Records and Diagnostics; [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Carry the example watches, or equivalent ones, in the host audit configuration and keep the msDS-KeyCredentialLink SACL in the Active Directory audit policy. The rules file has not been loaded on a live host by this assessment.

#### [V-222468] APSC-DV-000910 - The application must initiate session auditing upon startup.

- **Rule ID**: `SV-222468r960888_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001464`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Every run is bracketed by records in the host log. The launcher writes request started before any privileged step and request finished, or a failure record, when it ends. The detached maintainer writes maintenance started for its watched job and maintenance stopped or maintenance failed when it ends. Neither begins unless the host logging service takes the first record. The start and exit of each CRAFT process are also host events, recorded by the host audit service to which logging is deferred by the system owner's determination.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/maintain.hpp](../source/src/maintain.hpp): serve; [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Keep the AUTHPRIV facility in the host's retained and forwarded logs.

#### [V-222469] APSC-DV-000940 - The application must log application shutdown events.

- **Rule ID**: `SV-222469r960891_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000130`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Every run is bracketed by records in the host log. The launcher writes request started before any privileged step and request finished, or a failure record, when it ends. The detached maintainer writes maintenance started for its watched job and maintenance stopped or maintenance failed when it ends. Neither begins unless the host logging service takes the first record. The start and exit of each CRAFT process are also host events, recorded by the host audit service to which logging is deferred by the system owner's determination.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/maintain.hpp](../source/src/maintain.hpp): serve; [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Keep the AUTHPRIV facility in the host's retained and forwarded logs.

#### [V-222470] APSC-DV-000950 - The application must log destination IP addresses.

- **Rule ID**: `SV-222470r960891_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000130`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the host audit service by the system owner's determination. The official check accepts system logs for connections to supporting services such as DNS, AD or LDAP. CRAFT's connections to the KDC, the directory and CES are made inside the Kerberos, LDAP and HTTP libraries, so the host is the one place where every destination address can be recorded: an audit rule on connect for the worker and maintainer executables yields the remote address together with the login identity. source/config/craft.audit.rules supplies that rule.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/config/craft.audit.rules](../source/config/craft.audit.rules); [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/directory.hpp](../source/src/directory.hpp): ldap_connect; [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, get_tgt. Follow-up: Carry the connect rules in the host audit configuration and confirm a record for each enabled exchange. The rules file has not been loaded on a live host by this assessment.

#### [V-222471] APSC-DV-000960 - The application must log user actions involving access to data.

- **Rule ID**: `SV-222471r960891_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000130`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Closed by CRAFT's own records together with the host audit and logging services, to which logging is deferred by the system owner's determination. CRAFT records each request, issuance and failure, with the caller's UID and a request number, in the host AUTHPRIV log, and refuses to act when that service does not take a record. Reads of CRAFT's keys, keytab, configuration and trust files are host file accesses, recorded with the login identity by the STIG-compliant host audit service; source/config/craft.audit.rules supplies the watches. Access to the directory attribute is recorded by Active Directory auditing.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): audit, report; [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/config/craft.audit.rules](../source/config/craft.audit.rules); [source/README.md](../source/README.md): Audit Records and Diagnostics; [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Carry the example watches, or equivalent ones, in the host audit configuration and keep the msDS-KeyCredentialLink SACL in the Active Directory audit policy. The rules file has not been loaded on a live host by this assessment.

#### [V-222472] APSC-DV-000970 - The application must log user actions involving changes to data.

- **Rule ID**: `SV-222472r960891_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000130`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: CRAFT changes two objects and records both. Each Key Trust change to msDS-KeyCredentialLink produces a key credential added or key credential removed record naming the directory object and the worker; a refused change produces a failure record and a value left behind a CRITICAL one. Each cache replacement produces a request finished record with outcome=published, and each maintainer renewal a renewed TGT record before the cache is replaced. A change whose record the host logging service does not take is withdrawn or not made. Changes to CRAFT's own files are host file modifications, recorded by the host audit service to which logging is deferred by the system owner's determination.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/directory.hpp](../source/src/directory.hpp): KeyCredentialGuard, detach_key_credential; [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/maintain.hpp](../source/src/maintain.hpp): renew; [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/tests/tests.cpp](../source/tests/tests.cpp); [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Keep directory attribute-change auditing for msDS-KeyCredentialLink so that Active Directory records can be matched with CRAFT's.

#### [V-222473] APSC-DV-000980 - The application must produce audit records containing information to establish when (date and time) the events occurred.

- **Rule ID**: `SV-222473r960894_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000131`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Audit event timestamping, system-clock synchronization and UTC/GMT mapping are supplied by the compliant host/AD audit infrastructure. CRAFT already uses that OS logging path and POSIX clock; it does not implement a conflicting application time source.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Host/AD audit timestamp and authoritative time-source controls; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Maintain the inherited time source and preserve timestamp/timezone fields in forwarded events.

#### [V-222474] APSC-DV-000990 - The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event.

- **Rule ID**: `SV-222474r960897_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000132`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The audit helper uses the craft identifier and LOG_PID; the maintainer uses craft-maintain and LOG_PID. Emitted acquisition, renewal and cleanup messages distinguish outcomes and relevant operations; worker records include the requesting UID and success records include the username/source. These fields identify the emitting process/component and outcome. Missing events and incomplete caller identity are tracked separately and are not closed by this disposition.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/src/maintain.hpp](../source/src/maintain.hpp): update, serve. Follow-up: Preserve identifiers/outcomes in the deployed collector and resolve the separate event-coverage and user-identity findings.

#### [V-222475] APSC-DV-001000 - When using centralized logging; the application must include a unique identifier in order to distinguish itself from other application logs.

- **Rule ID**: `SV-222475r960900_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000133`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. The host logging system preserves originating-host identity, while CRAFT supplies craft or craft-maintain and LOG_PID. Together these distinguish the program and source system in centrally collected records.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-653060; host/AD source-system labeling controls; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve. Follow-up: Preserve source-system and program identifiers when changing the collector or forwarding format.

#### [V-222476] APSC-DV-001010 - The application must produce audit records that contain information to establish the outcome of the events.

- **Rule ID**: `SV-222476r960903_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000134`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The audit helper uses the craft identifier and LOG_PID; the maintainer uses craft-maintain and LOG_PID. Emitted acquisition, renewal and cleanup messages distinguish outcomes and relevant operations; worker records include the requesting UID and success records include the username/source. These fields identify the emitting process/component and outcome. Missing events and incomplete caller identity are tracked separately and are not closed by this disposition.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/src/maintain.hpp](../source/src/maintain.hpp): update, serve. Follow-up: Preserve identifiers/outcomes in the deployed collector and resolve the separate event-coverage and user-identity findings.

#### [V-222477] APSC-DV-001020 - The application must generate audit records containing information that establishes the identity of any individual or process associated with the event.

- **Rule ID**: `SV-222477r960906_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001487`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The audit helper uses the craft identifier and LOG_PID; the maintainer uses craft-maintain and LOG_PID. Emitted acquisition, renewal and cleanup messages distinguish outcomes and relevant operations; worker records include the requesting UID and success records include the username/source. These fields identify the emitting process/component and outcome. Missing events and incomplete caller identity are tracked separately and are not closed by this disposition.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/worker.cpp](../source/src/worker.cpp): main; [source/src/maintain.hpp](../source/src/maintain.hpp): update, serve. Follow-up: Preserve identifiers/outcomes in the deployed collector and resolve the separate event-coverage and user-identity findings.

#### [V-222482] APSC-DV-001080 - The application must be configured to write application logs to a centralized log repository.

- **Rule ID**: `SV-222482r961860_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001851`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. The compliant host sends its audit/log records, including CRAFT's native AUTHPRIV records, to the central repository through the governed OS forwarding service. CRAFT does not need its own remote-log client for this requirement.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-652040 through RHEL-09-652055; host log forwarding; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve; [source/SECURITY.md](../source/SECURITY.md). Follow-up: Preserve the native application facility in the host forwarding policy. This closure does not establish producer acknowledgement, custom reporting, cryptographic archive seals or ASD retention periods.

#### [V-222483] APSC-DV-001090 - The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

- **Rule ID**: `SV-222483r961398_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001855`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Audit repository capacity monitoring and required SA/ISSO warnings at 75 percent utilization are provided by the inherited host logging/audit storage controls. CRAFT stores its events through that infrastructure rather than managing a private audit volume.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-653035, RHEL-09-653040; host audit-storage capacity alarms; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve; [source/SECURITY.md](../source/SECURITY.md). Follow-up: Retain inherited capacity alarming for repositories holding CRAFT events. Apply equivalent controls if events are moved into a new application-specific repository.

#### [V-222484] APSC-DV-001100 - Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events.

- **Rule ID**: `SV-222484r961401_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001858`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Audit-provider processing/storage failure alerts to the required administrators are supplied by the compliant underlying audit/logging services. CRAFT does not need to duplicate those backend alarms. This is an inheritance closure for audit-provider failures. Submission from CRAFT to the provider is checked by CRAFT itself and assessed under V-222486.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-653070, RHEL-09-653125; host/AD audit-provider failure notification; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve; [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain inherited audit-provider alert recipients and failure responses. Address application submission/continuation behavior under V-222486 and test that boundary during acceptance.

#### [V-222485] APSC-DV-001110 - The application must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.

- **Rule ID**: `SV-222485r960912_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000139`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Audit-provider processing/storage failure alerts to the required administrators are supplied by the compliant underlying audit/logging services. CRAFT does not need to duplicate those backend alarms. This is an inheritance closure for audit-provider failures. Submission from CRAFT to the provider is checked by CRAFT itself and assessed under V-222486.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-653070, RHEL-09-653125; host/AD audit-provider failure notification; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve; [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain inherited audit-provider alert recipients and failure responses. Address application submission/continuation behavior under V-222486 and test that boundary during acceptance.

#### [V-222486] APSC-DV-001120 - The application must shut down by default upon audit failure (unless availability is an overriding concern).

- **Rule ID**: `SV-222486r1043188_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000140`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: CRAFT halts on a detected audit failure. Each record is sent to the host logging socket and the result is checked: when the service does not take a record the launcher does not start, the worker releases no credentials, a published Key Trust key is withdrawn and the maintainer does not publish a renewal. What follows acceptance by the host service (storage, forwarding, capacity alarms and the response to their failure) is deferred to the STIG-compliant OS logging and audit configuration by the system owner's determination.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): audit, try_audit; [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/key-trust.cpp](../source/tests/key-trust.cpp); [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Keep the host logging service's own failure response in the OS assessment; CRAFT confirms submission only as far as the local socket.

#### [V-222497] APSC-DV-001250 - The applications must use internal system clocks to generate time stamps for audit records.

- **Rule ID**: `SV-222497r960927_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000159`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: CRAFT delegates audit timestamp generation to the underlying syslog service and uses the internal POSIX system clock for its own credential/expiry time values. It does not accept user-supplied audit timestamps. Collector format, UTC mapping and synchronization remain separate deployment review items.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp)

#### [V-222498] APSC-DV-001260 - The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).

- **Rule ID**: `SV-222498r961443_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001890`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Audit event timestamping, system-clock synchronization and UTC/GMT mapping are supplied by the compliant host/AD audit infrastructure. CRAFT already uses that OS logging path and POSIX clock; it does not implement a conflicting application time source.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Host/AD audit timestamp and authoritative time-source controls; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Maintain the inherited time source and preserve timestamp/timezone fields in forwarded events.

#### [V-222500] APSC-DV-001280 - The application must protect audit information from any type of unauthorized read access.

- **Rule ID**: `SV-222500r960930_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000162`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. The compliant host/AD logging repositories enforce authorized read, modification and deletion permissions for audit information and configuration. CRAFT writes to the native protected audit facility, not to a caller-owned application log file.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-653080 through RHEL-09-653090; host/AD protected audit repositories; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve. Follow-up: Preserve access restrictions on local, forwarded and archived events when changing their storage location.

#### [V-222501] APSC-DV-001290 - The application must protect audit information from unauthorized modification.

- **Rule ID**: `SV-222501r960933_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000163`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. The compliant host/AD logging repositories enforce authorized read, modification and deletion permissions for audit information and configuration. CRAFT writes to the native protected audit facility, not to a caller-owned application log file.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-653080 through RHEL-09-653090; host/AD protected audit repositories; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve. Follow-up: Preserve access restrictions on local, forwarded and archived events when changing their storage location.

#### [V-222502] APSC-DV-001300 - The application must protect audit information from unauthorized deletion.

- **Rule ID**: `SV-222502r960936_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000164`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. The compliant host/AD logging repositories enforce authorized read, modification and deletion permissions for audit information and configuration. CRAFT writes to the native protected audit facility, not to a caller-owned application log file.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-653080 through RHEL-09-653090; host/AD protected audit repositories; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve. Follow-up: Preserve access restrictions on local, forwarded and archived events when changing their storage location.

#### [V-222511] APSC-DV-001410 - The application must enforce access restrictions associated with changes to application configuration.

- **Rule ID**: `SV-222511r961461_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001813`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: root_open rejects non-root-owned or group/world-writable administrator-controlled path components and unsafe file types. Caller-home and private-file checks enforce caller ownership and restricted writes. Ordinary caller data cannot supply alternate system configuration or trust paths. These are implemented DAC and configuration write-protection mechanisms.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): root_open, caller_home, open_private; [source/src/config.hpp](../source/src/config.hpp): config; [source/src/x509.hpp](../source/src/x509.hpp): user_identity_files. Follow-up: Maintain the documented installation permissions and verify the effective deployed access policy.

#### [V-222512] APSC-DV-001420 - The application must audit who makes configuration changes to the application.

- **Rule ID**: `SV-222512r1015690_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003938`, `CCI-001814`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the host audit service by the system owner's determination. CRAFT's configuration, trust files, CRLs and executables are root-controlled host files with no application editing interface; the host audit service records each change with the administrator's login identity. source/config/craft.audit.rules supplies watches for /etc/craft and the installed programs.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/config/craft.audit.rules](../source/config/craft.audit.rules); [source/src/common.hpp](../source/src/common.hpp): root_open; [source/README.md](../source/README.md): Shared Linux installation. Follow-up: Carry the example watches, or equivalent ones, in the host audit configuration.

#### [V-222514] APSC-DV-001440 - The applications must limit privileges to change the software resident within software libraries.

- **Rule ID**: `SV-222514r960960_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001499`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Installed OS libraries, NSS modules, Kerberos plugins and cryptographic providers are protected by the compliant platform's ownership, write restrictions and authorized update process. The descriptor-verified CRAFT worker and cleared environment complement those restrictions.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Host software/library ownership and authorized-update controls; [source/src/common.hpp](../source/src/common.hpp): root_open; [source/src/common.hpp](../source/src/common.hpp): root_open; [source/CMakeLists.txt](../source/CMakeLists.txt); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Use administrator-controlled OS library/plugin paths. A new bundled library or caller-writable plugin path falls outside this inherited platform scope.

#### [V-222516] APSC-DV-001480 - The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.

- **Rule ID**: `SV-222516r961473_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001764`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the platform mechanisms that enforce it. Who may run the privileged launcher is host access control: the craft-users group on a mode-04750 launcher. Service secrets are readable only by root and the unprivileged craft service account. What the service identity may do is set by AD CS enrollment-agent restrictions and by the directory delegation on msDS-KeyCredentialLink. CRAFT adds no authorization store of its own, runs its worker without root and drops privilege permanently before it handles credentials.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/common.hpp](../source/src/common.hpp): drop, root_open; [source/README.md](../source/README.md): Shared privileged installation; [scripts/Configure-CRAFT-CA.ps1](../scripts/Configure-CRAFT-CA.ps1): Assert-CAEnrollmentPolicy; [scripts/Grant-CRAFTKeyCredentialLink.ps1](../scripts/Grant-CRAFTKeyCredentialLink.ps1); [source/TESTING.md](../source/TESTING.md): Multi-OS Validation. Follow-up: Keep the launcher group, CA restrictions and delegation scope in the host and AD configuration baselines.

#### [V-222519] APSC-DV-001510 - The application must be configured to use only functions, ports, and protocols permitted to it in the PPSM CAL.

- **Rule ID**: `SV-222519r1043177_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000382`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT listens on no port and adds no network service. Its outbound connections use the Kerberos, LDAP and Global Catalog, and HTTPS services of AD DS and AD CS on their standard ports, whose approval and registration belong to those platforms; the host firewall, under the OS STIG, limits what the host may reach.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/config/config.example](../source/config/config.example); [source/config/krb5.conf.example](../source/config/krb5.conf.example). Follow-up: List CRAFT's destinations (KDC, domain controller and Global Catalog, CES) in the host's existing ports-and-protocols record if the site records client flows.

#### [V-222522] APSC-DV-001540 - The application must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

- **Rule ID**: `SV-222522r1263550_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000764`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The launcher takes the real UID, resolves its NSS name/home, and passes only that caller identity to the fixed worker. The worker revalidates UID/name and requests <name>@<configured realm>; validate_tgt verifies the returned client and TGT-server principals. Enrollment/Key Trust bind the certificate UPN to the directory lookup. Home mode relies on the KDC's certificate mapping, not an invented local LDAP comparison.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/common.hpp](../source/src/common.hpp): lookup_uid; [source/src/worker.cpp](../source/src/worker.cpp); [source/src/x509.hpp](../source/src/x509.hpp): validate_leaf; [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt, validate_tgt. Follow-up: Verify trusted host/NSS authentication, intended AD/KDC mappings and denial of mismatched identities in the deployed environment; this is not MFA evidence.

#### [V-222523] APSC-DV-001550 - The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.

- **Rule ID**: `SV-222523r960972_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000765`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Multifactor authentication is inherited from operating-system logon by the system owner's determination: users reach CRAFT only from a host session authenticated under the OS STIG, and administrators must authenticate with MFA to install or administer it. CRAFT presents no logon interface of its own. It acts for the already authenticated host user, and its unattended PKINIT is automation that the host session authorizes, not a separate logon. CRAFT has no privileged application account: administration is root access to the host.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (MFA inherited from OS logon); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/pkinit.hpp](../source/src/pkinit.hpp): refuse_prompt; [source/SECURITY.md](../source/SECURITY.md): Trust Decision. Follow-up: Reassess if CRAFT is offered to anyone who does not first authenticate to the host, or if a deployment requires a fresh token challenge for each issuance.

#### [V-222524] APSC-DV-001560 - The application must accept Personal Identity Verification (PIV) credentials.

- **Rule ID**: `SV-222524r1263551_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001953`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Multifactor authentication is inherited from operating-system logon by the system owner's determination: users reach CRAFT only from a host session authenticated under the OS STIG, and administrators must authenticate with MFA to install or administer it. CRAFT presents no logon interface of its own. It acts for the already authenticated host user, and its unattended PKINIT is automation that the host session authorizes, not a separate logon.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (MFA inherited from OS logon); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/pkinit.hpp](../source/src/pkinit.hpp): refuse_prompt; [source/SECURITY.md](../source/SECURITY.md): Trust Decision. Follow-up: Reassess if CRAFT is offered to anyone who does not first authenticate to the host, or if a deployment requires a fresh token challenge for each issuance.

#### [V-222525] APSC-DV-001570 - The application must electronically verify Personal Identity Verification (PIV) credentials.

- **Rule ID**: `SV-222525r1263552_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001954`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Multifactor authentication is inherited from operating-system logon by the system owner's determination: users reach CRAFT only from a host session authenticated under the OS STIG, and administrators must authenticate with MFA to install or administer it. CRAFT presents no logon interface of its own. It acts for the already authenticated host user, and its unattended PKINIT is automation that the host session authorizes, not a separate logon.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (MFA inherited from OS logon); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/pkinit.hpp](../source/src/pkinit.hpp): refuse_prompt; [source/SECURITY.md](../source/SECURITY.md): Trust Decision. Follow-up: Reassess if CRAFT is offered to anyone who does not first authenticate to the host, or if a deployment requires a fresh token challenge for each issuance.

#### [V-222526] APSC-DV-001580 - The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.

- **Rule ID**: `SV-222526r1263553_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000766`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Multifactor authentication is inherited from operating-system logon by the system owner's determination: users reach CRAFT only from a host session authenticated under the OS STIG, and administrators must authenticate with MFA to install or administer it. CRAFT presents no logon interface of its own. It acts for the already authenticated host user, and its unattended PKINIT is automation that the host session authorizes, not a separate logon.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (MFA inherited from OS logon); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/pkinit.hpp](../source/src/pkinit.hpp): refuse_prompt; [source/SECURITY.md](../source/SECURITY.md): Trust Decision. Follow-up: Reassess if CRAFT is offered to anyone who does not first authenticate to the host, or if a deployment requires a fresh token challenge for each issuance.

#### [V-222527] APSC-DV-001590 - The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.

- **Rule ID**: `SV-222527r1015693_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000765`, `CCI-000767`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Multifactor authentication is inherited from operating-system logon by the system owner's determination: users reach CRAFT only from a host session authenticated under the OS STIG, and administrators must authenticate with MFA to install or administer it. CRAFT presents no logon interface of its own. It acts for the already authenticated host user, and its unattended PKINIT is automation that the host session authorizes, not a separate logon. CRAFT has no privileged application account: administration is root access to the host.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (MFA inherited from OS logon); [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/pkinit.hpp](../source/src/pkinit.hpp): refuse_prompt; [source/SECURITY.md](../source/SECURITY.md): Trust Decision. Follow-up: Reassess if CRAFT is offered to anyone who does not first authenticate to the host, or if a deployment requires a fresh token challenge for each issuance.

#### [V-222528] APSC-DV-001600 - The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged accounts.

- **Rule ID**: `SV-222528r1263554_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000766`, `CCI-000768`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT is a local tool that inherits the authenticated host user's real UID and does not supply an alternate local logon interface. The required local user authentication/MFA is provided by the compliant host access policy. The network and PIV controls are closed the same way, by the system owner's determination that MFA is inherited from host logon.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Host local-access MFA/authentication controls; [source/src/launcher.cpp](../source/src/launcher.cpp): main; [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp): refuse_prompt; [source/SECURITY.md](../source/SECURITY.md). Follow-up: Keep permitted interactive and scheduled entry paths governed by the inherited host policy. Unattended network credential issuance is covered by the system owner's determination of 11 October 2026.

#### [V-222530] APSC-DV-001620 - The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.

- **Rule ID**: `SV-222530r1263556_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001941`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Replay resistance is that of Kerberos and PKINIT, implemented by the OS Kerberos libraries and the domain KDC with timestamps, nonces and freshness tokens. CRAFT implements no authentication protocol of its own.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS and AD); [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt. Follow-up: Keep host clocks synchronized as the OS STIG requires.

#### [V-222531] APSC-DV-001630 - The application must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.

- **Rule ID**: `SV-222531r1263558_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001941`, `CCI-001942`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Replay resistance is that of Kerberos and PKINIT, implemented by the OS Kerberos libraries and the domain KDC with timestamps, nonces and freshness tokens. CRAFT implements no authentication protocol of its own.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS and AD); [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt. Follow-up: Keep host clocks synchronized as the OS STIG requires.

#### [V-222549] APSC-DV-001800 - The application must terminate existing user sessions upon account deletion.

- **Rule ID**: `SV-222549r961521_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002007`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to Active Directory. CRAFT holds no sessions: tickets are issued and bounded by the KDC. Deleting or disabling the directory account prevents further issuance and renewal, and tickets already issued end under the domain ticket policy.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS and AD); [source/SECURITY.md](../source/SECURITY.md): Lifetime and Encryption Policy. Follow-up: None for CRAFT; ticket lifetime is the domain's policy.

#### [V-222551] APSC-DV-001820 - The application, when using PKI-based authentication, must enforce authorized access to the corresponding private key.

- **Rule ID**: `SV-222551r961041_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000186`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Home key reads occur as the caller and reject unsafe ownership, symlinks, extra hard links and group/other access. Service-secret paths must be root-owned, non-writable by group/others and inaccessible to other users. Generated keys are passed through mode-0600 sealed memfd objects; core dumps/dumpability are disabled. These access controls do not imply at-rest encryption, locked memory or complete secure erasure.
- **Comments / Evidence**: Evidence: [source/src/x509.hpp](../source/src/x509.hpp): user_identity_files, load_key; [source/src/common.hpp](../source/src/common.hpp): open_private, root_open, no_core; [source/src/pkinit.hpp](../source/src/pkinit.hpp): memory_file, pem_file. Follow-up: Verify that the deployed service group contains only authorized identities and that unauthorized users cannot read any key/keytab/cache.

#### [V-222552] APSC-DV-001830 - The application must map the authenticated identity to the individual user or group account for PKI-based authentication.

- **Rule ID**: `SV-222552r961044_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000187`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The launcher takes the real UID, resolves its NSS name/home, and passes only that caller identity to the fixed worker. The worker revalidates UID/name and requests <name>@<configured realm>; validate_tgt verifies the returned client and TGT-server principals. Enrollment/Key Trust bind the certificate UPN to the directory lookup. Home mode relies on the KDC's certificate mapping, not an invented local LDAP comparison.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/common.hpp](../source/src/common.hpp): lookup_uid; [source/src/worker.cpp](../source/src/worker.cpp); [source/src/x509.hpp](../source/src/x509.hpp): validate_leaf; [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt, validate_tgt. Follow-up: Verify trusted host/NSS authentication, intended AD/KDC mappings and denial of mismatched identities in the deployed environment; this is not MFA evidence.

#### [V-222556] APSC-DV-001870 - The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

- **Rule ID**: `SV-222556r961053_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000804`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the host and Active Directory identity services under the system owner's determination that authentication is inherited from the OS. CRAFT identifies and authenticates no one itself: it accepts the NSS-resolved account of an already authenticated host session and requests a ticket for the matching directory account. Whether non-organizational users, other agencies' PIV credentials or FICAM-approved credentials are accepted is decided where those users log on.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (authentication inherited from OS logon); [source/src/common.hpp](../source/src/common.hpp): lookup_uid; [source/src/launcher.cpp](../source/src/launcher.cpp): main. Follow-up: Reassess if a deployment admits partner users by a path that bypasses host logon.

#### [V-222557] APSC-DV-001880 - The application must accept Personal Identity Verification (PIV) credentials from other federal agencies.

- **Rule ID**: `SV-222557r1263578_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002009`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the host and Active Directory identity services under the system owner's determination that authentication is inherited from the OS. CRAFT identifies and authenticates no one itself: it accepts the NSS-resolved account of an already authenticated host session and requests a ticket for the matching directory account. Whether non-organizational users, other agencies' PIV credentials or FICAM-approved credentials are accepted is decided where those users log on.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (authentication inherited from OS logon); [source/src/common.hpp](../source/src/common.hpp): lookup_uid; [source/src/launcher.cpp](../source/src/launcher.cpp): main. Follow-up: Reassess if a deployment admits partner users by a path that bypasses host logon.

#### [V-222558] APSC-DV-001890 - The application must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.

- **Rule ID**: `SV-222558r1263581_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002010`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the host and Active Directory identity services under the system owner's determination that authentication is inherited from the OS. CRAFT identifies and authenticates no one itself: it accepts the NSS-resolved account of an already authenticated host session and requests a ticket for the matching directory account. Whether non-organizational users, other agencies' PIV credentials or FICAM-approved credentials are accepted is decided where those users log on.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (authentication inherited from OS logon); [source/src/common.hpp](../source/src/common.hpp): lookup_uid; [source/src/launcher.cpp](../source/src/launcher.cpp): main. Follow-up: Reassess if a deployment admits partner users by a path that bypasses host logon.

#### [V-222559] APSC-DV-001900 - The application must accept Federal Identity, Credential, and Access Management (FICAM)-approved third-party credentials.

- **Rule ID**: `SV-222559r1015708_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004083`, `CCI-002011`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the host and Active Directory identity services under the system owner's determination that authentication is inherited from the OS. CRAFT identifies and authenticates no one itself: it accepts the NSS-resolved account of an already authenticated host session and requests a ticket for the matching directory account. Whether non-organizational users, other agencies' PIV credentials or FICAM-approved credentials are accepted is decided where those users log on.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (authentication inherited from OS logon); [source/src/common.hpp](../source/src/common.hpp): lookup_uid; [source/src/launcher.cpp](../source/src/launcher.cpp): main. Follow-up: Reassess if a deployment admits partner users by a path that bypasses host logon.

#### [V-222560] APSC-DV-001910 - The application must conform to Federal Identity, Credential, and Access Management (FICAM)-issued profiles.

- **Rule ID**: `SV-222560r1263583_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004085`, `CCI-002014`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the host and Active Directory identity services under the system owner's determination that authentication is inherited from the OS. CRAFT identifies and authenticates no one itself: it accepts the NSS-resolved account of an already authenticated host session and requests a ticket for the matching directory account. Whether non-organizational users, other agencies' PIV credentials or FICAM-approved credentials are accepted is decided where those users log on.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (authentication inherited from OS logon); [source/src/common.hpp](../source/src/common.hpp): lookup_uid; [source/src/launcher.cpp](../source/src/launcher.cpp): main. Follow-up: Reassess if a deployment admits partner users by a path that bypasses host logon.

#### [V-222568] APSC-DV-002000 - The application must terminate all network connections associated with a communications session at the end of the session.

- **Rule ID**: `SV-222568r961068_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001133`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: LDAP handles unbind through ScopedLdap ownership, curl handles are released at the end of CES operations, and Kerberos contexts/caches are RAII-owned. Network exchanges occur in bounded acquisition/update operations; process termination releases remaining sockets. CRAFT does not intentionally retain a user communication session after the corresponding process/operation ends.
- **Comments / Evidence**: Evidence: [source/src/directory.hpp](../source/src/directory.hpp): free_ldap, ScopedLdap; [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/pkinit.hpp](../source/src/pkinit.hpp): Kerberos; [source/src/maintain.hpp](../source/src/maintain.hpp): update. Follow-up: Confirm connection closure under live timeout/termination tests in the deployment.

#### [V-222571] APSC-DV-002030 - The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.

- **Rule ID**: `SV-222571r1263587_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002450`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Hashes computed at run time use the OS-supplied cryptographic module. Hashing of release components does not apply, because CRAFT is distributed as source only by the system owner's determination. The SHA-256 fields of a Key Trust credential are fixed by the protocol.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (source-only distribution); [source/src/directory.hpp](../source/src/directory.hpp): sha256, key_credential_blob. Follow-up: A National Security System designation, with its SHA-384 minimum, remains part of the deployment data profile.

#### [V-222572] APSC-DV-002040 - The application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.

- **Rule ID**: `SV-222572r1117181_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002450`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses the administrator-controlled OS OpenSSL/Kerberos/GSSAPI/TLS libraries and does not select a private provider or disable their system cryptographic policy. Under the supplied platform-compliance assumption those cryptographic modules and policies are validated/approved for protected unclassified exchanges and key exchange. Source adds RSA-size, verified HTTPS and AES-ticket restrictions; a second application-managed FIPS configuration is unnecessary.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-671010, RHEL-09-215105; WN22-SO-000360; approved OS cryptographic modules; [source/CMakeLists.txt](../source/CMakeLists.txt); [source/src/x509.hpp](../source/src/x509.hpp): generate_key; [source/src/enroll.hpp](../source/src/enroll.hpp): wrap_eobo, send_ces; [source/src/directory.hpp](../source/src/directory.hpp): sha256; [source/src/pkinit.hpp](../source/src/pkinit.hpp). Follow-up: Build/deploy against the governed OS libraries and policy. Independently built/bundled modules, component release signing, NSS-specific hash requirements and classified-data requirements remain separate.

#### [V-222574] APSC-DV-002150 - The application user interface must be either physically or logically separated from data storage and management interfaces.

- **Rule ID**: `SV-222574r1117171_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001082`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The fixed caller-facing acquisition entry point does not provide an administrator management interface. Administrator configuration/trust resides in root-controlled paths, while the published user credential cache resides in the NSS home. Runtime worker IPC is a private pipe and does not expose a management listener.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/common.hpp](../source/src/common.hpp): root_open, publish_cache; [source/src/config.hpp](../source/src/config.hpp); [source/README.md](../source/README.md)

#### [V-222586] APSC-DV-002320 - In the event of a system failure, applications must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.

- **Rule ID**: `SV-222586r961125_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001665`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The cause of every failure is recorded in the host log, to which logging is deferred by the system owner's determination, with the request and caller it belongs to. CRAFT keeps no state between runs that must be preserved to bring it back: a failed run leaves the previous cache in place and the next run starts afresh.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): report; [source/src/maintain.hpp](../source/src/maintain.hpp): record_failure; [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Residual Key Trust values after a directory or host failure remain assessed under V-222585.

#### [V-222587] APSC-DV-002330 - The application must protect the confidentiality and integrity of stored information when required by DoW policy or the information owner.

- **Rule ID**: `SV-222587r1263591_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001199`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the OS. Everything CRAFT stores is a host file: the caller's mode-0600 ticket cache and home certificate pair, and root-controlled service secrets readable only by the service account. Their confidentiality and integrity at rest are the host's access control and, where the data owner requires it, the host's approved storage encryption. CRAFT adds no storage format of its own; the cache is the standard Kerberos FILE cache.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): open_private, replace_file, root_open; [source/SECURITY.md](../source/SECURITY.md): User Credential Storage. Follow-up: Apply host storage and swap encryption to credential-bearing volumes where the data owner requires it.

#### [V-222588] APSC-DV-002340 - The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.

- **Rule ID**: `SV-222588r1263593_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-002475`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the OS. Everything CRAFT stores is a host file: the caller's mode-0600 ticket cache and home certificate pair, and root-controlled service secrets readable only by the service account. Their confidentiality and integrity at rest are the host's access control and, where the data owner requires it, the host's approved storage encryption. CRAFT adds no storage format of its own; the cache is the standard Kerberos FILE cache.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): open_private, replace_file, root_open; [source/SECURITY.md](../source/SECURITY.md): User Credential Storage. Follow-up: Apply host storage and swap encryption to credential-bearing volumes where the data owner requires it.

#### [V-222589] APSC-DV-002350 - The application must use appropriate cryptography in order to protect stored DoW information when required by the information owner or DoW policy.

- **Rule ID**: `SV-222589r1263595_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-002476`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the OS. Everything CRAFT stores is a host file: the caller's mode-0600 ticket cache and home certificate pair, and root-controlled service secrets readable only by the service account. Their confidentiality and integrity at rest are the host's access control and, where the data owner requires it, the host's approved storage encryption. CRAFT adds no storage format of its own; the cache is the standard Kerberos FILE cache.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): open_private, replace_file, root_open; [source/SECURITY.md](../source/SECURITY.md): User Credential Storage. Follow-up: Apply host storage and swap encryption to credential-bearing volumes where the data owner requires it.

#### [V-222590] APSC-DV-002360 - The application must isolate security functions from non-security functions.

- **Rule ID**: `SV-222590r961131_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001084`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The launcher executes a descriptor-verified worker in a separate process with cleared environment and restricted inherited descriptors. Home work runs as the caller; privileged fallback work runs under the dedicated service account; the parent drops privilege before credential transfer/publication. Private pipes, file ownership, no-core/non-dumpable settings and sealed mode-0600 memfd objects provide process/resource boundaries. Memory is not mlocked and root/service-account compromise remains in the trust model.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/common.hpp](../source/src/common.hpp): drop, keep_only, no_core; [source/src/pkinit.hpp](../source/src/pkinit.hpp): memory_file; [source/SECURITY.md](../source/SECURITY.md). Follow-up: Preserve host process isolation and deployed account/group restrictions; verify privilege and descriptor boundaries before installation.

#### [V-222591] APSC-DV-002370 - The application must maintain a separate execution domain for each executing process.

- **Rule ID**: `SV-222591r1117179_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002530`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The launcher executes a descriptor-verified worker in a separate process with cleared environment and restricted inherited descriptors. Home work runs as the caller; privileged fallback work runs under the dedicated service account; the parent drops privilege before credential transfer/publication. Private pipes, file ownership, no-core/non-dumpable settings and sealed mode-0600 memfd objects provide process/resource boundaries. Memory is not mlocked and root/service-account compromise remains in the trust model.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/common.hpp](../source/src/common.hpp): drop, keep_only, no_core; [source/src/pkinit.hpp](../source/src/pkinit.hpp): memory_file; [source/SECURITY.md](../source/SECURITY.md). Follow-up: Preserve host process isolation and deployed account/group restrictions; verify privilege and descriptor boundaries before installation.

#### [V-222592] APSC-DV-002380 - Applications must prevent unauthorized and unintended information transfer via shared system resources.

- **Rule ID**: `SV-222592r1263596_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001090`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The launcher executes a descriptor-verified worker in a separate process with cleared environment and restricted inherited descriptors. Home work runs as the caller; privileged fallback work runs under the dedicated service account; the parent drops privilege before credential transfer/publication. Private pipes, file ownership, no-core/non-dumpable settings and sealed mode-0600 memfd objects provide process/resource boundaries. Memory is not mlocked and root/service-account compromise remains in the trust model.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/common.hpp](../source/src/common.hpp): drop, keep_only, no_core; [source/src/pkinit.hpp](../source/src/pkinit.hpp): memory_file; [source/SECURITY.md](../source/SECURITY.md). Follow-up: Preserve host process isolation and deployed account/group restrictions; verify privilege and descriptor boundaries before installation.

#### [V-222593] APSC-DV-002390 - XML-based applications must mitigate DoS attacks by using XML filters, parser options, or gateways.

- **Rule ID**: `SV-222593r961620_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002385`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The CES response parser limits responses to 2 MiB, rejects DOCTYPE/ENTITY declarations and document subsets, and enables XML_PARSE_NONET without DTD loading, entity substitution or huge-document mode. The worker additionally has CPU/address-space and execution deadlines. This implements XML DoS mitigations; it is not proof that every parser/library vulnerability is absent.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp): receive, parse_soap; [source/src/worker.cpp](../source/src/worker.cpp); [source/tests/tests.cpp](../source/tests/tests.cpp). Follow-up: Keep the parser library supported and complete the separately required XML vulnerability/fuzz assessment.

#### [V-222595] APSC-DV-002410 - The web service design must include redundancy mechanisms when used with high-availability systems.

- **Rule ID**: `SV-222595r961155_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001095`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT is a client and has no service to make redundant. Redundancy of the KDC, directory and CES it depends on is that of the AD DS and AD CS infrastructure.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS and AD). Follow-up: None for CRAFT.

#### [V-222596] APSC-DV-002440 - The application must protect the confidentiality and integrity of transmitted information.

- **Rule ID**: `SV-222596r961632_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-002418`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. The application implements verified CES HTTPS, confidentiality/integrity-protected LDAP/GSSAPI with minimum SSF 128 and PKINIT/Kerberos credential protection. The compliant OS/domain supply the approved algorithms and modules. This general transport check permits TLS, IPsec or other approved mechanisms, so it does not require replacing protected GSSAPI with LDAPS. Protocol routing metadata is not represented as encrypted, and TLS-specific/multihop checks remain separate.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Approved OS/domain cryptography; RHEL-09-215105; ASD approved-transport-mechanism check; [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/directory.hpp](../source/src/directory.hpp): ldap_connect; [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/config/krb5.conf.example](../source/config/krb5.conf.example). Follow-up: Preserve peer verification, SSF and ticket checks. Resolve the distinct TLS-specific applicability and SOAP/multihop requirements without weakening the supported AD protocol profile.

#### [V-222597] APSC-DV-002450 - The application must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).

- **Rule ID**: `SV-222597r1117180_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002421`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Transmitted information is protected by the OS's approved cryptographic modules: TLS 1.2 or later for CES, the GSSAPI security layer for directory traffic and Kerberos for the credential exchanges. CRAFT implements no cryptographic transport of its own.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/directory.hpp](../source/src/directory.hpp): ldap_connect; [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt. Follow-up: The check text names TLS; directory traffic uses the GSSAPI security layer because Active Directory refuses that layer inside TLS. An assessor must accept it as the equivalent.

#### [V-222598] APSC-DV-002460 - The application must maintain the confidentiality and integrity of information during preparation for transmission.

- **Rule ID**: `SV-222598r961638_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002420`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Transmitted information is protected by the OS's approved cryptographic modules: TLS 1.2 or later for CES, the GSSAPI security layer for directory traffic and Kerberos for the credential exchanges. CRAFT implements no cryptographic transport of its own.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/directory.hpp](../source/src/directory.hpp): ldap_connect; [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt. Follow-up: The check text names TLS; directory traffic uses the GSSAPI security layer because Active Directory refuses that layer inside TLS. An assessor must accept it as the equivalent.

#### [V-222599] APSC-DV-002470 - The application must maintain the confidentiality and integrity of information during reception.

- **Rule ID**: `SV-222599r961641_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002422`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Transmitted information is protected by the OS's approved cryptographic modules: TLS 1.2 or later for CES, the GSSAPI security layer for directory traffic and Kerberos for the credential exchanges. CRAFT implements no cryptographic transport of its own.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/directory.hpp](../source/src/directory.hpp): ldap_connect; [source/src/pkinit.hpp](../source/src/pkinit.hpp): get_tgt. Follow-up: The check text names TLS; directory traffic uses the GSSAPI security layer because Active Directory refuses that layer inside TLS. An assessor must accept it as the equivalent.

#### [V-222600] APSC-DV-002480 - The application must not disclose unnecessary information to users.

- **Rule ID**: `SV-222600r961638_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002420`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Callers receive a summary of what failed and a reference to the log. System paths, configuration keys, CES fault text and library messages go only to the host AUTHPRIV log, which the OS restricts to administrators. Every failure carries a summary and separate detail, and the outer handlers of the launcher, the worker, their child processes and the maintainer print the summary alone. Messages printed by libxml2 are discarded. The maintainer's status file follows the same rule.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): Failure, caller_notice, report, root_open; [source/src/enroll.hpp](../source/src/enroll.hpp): parse_soap, reject_fault; [source/src/maintain.hpp](../source/src/maintain.hpp): record_failure; [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Review the caller-visible summaries again when a failure path is added.

#### [V-222604] APSC-DV-002510 - The application must protect from command injection.

- **Rule ID**: `SV-222604r961158_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-001310`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The privileged runtime uses a fixed descriptor-verified fexecve target and explicit argument vector rather than a command shell, system or popen. Caller names are constrained by simple_name before being used in identities/directory filters. The optional with-craft wrapper executes its caller-supplied command as that same user through a quoted argument vector; it does not grant arbitrary commands worker privilege.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/common.hpp](../source/src/common.hpp): simple_name; [source/src/maintain.hpp](../source/src/maintain.hpp): enroll; [source/scripts/with-craft.in](../source/scripts/with-craft.in). Follow-up: Maintain fixed privileged executable paths and verify the separately provisioned administration helpers in their own execution context.

#### [V-222610] APSC-DV-002570 - The application must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.

- **Rule ID**: `SV-222610r961167_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001312`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Callers receive a summary of what failed and a reference to the log. System paths, configuration keys, CES fault text and library messages go only to the host AUTHPRIV log, which the OS restricts to administrators. Every failure carries a summary and separate detail, and the outer handlers of the launcher, the worker, their child processes and the maintainer print the summary alone. Messages printed by libxml2 are discarded. The maintainer's status file follows the same rule.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): Failure, caller_notice, report, root_open; [source/src/enroll.hpp](../source/src/enroll.hpp): parse_soap, reject_fault; [source/src/maintain.hpp](../source/src/maintain.hpp): record_failure; [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Review the caller-visible summaries again when a failure path is added.

#### [V-222611] APSC-DV-002580 - The application must reveal error messages only to the ISSO, ISSM, or SA.

- **Rule ID**: `SV-222611r961170_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001314`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Callers receive a summary of what failed and a reference to the log. System paths, configuration keys, CES fault text and library messages go only to the host AUTHPRIV log, which the OS restricts to administrators. Every failure carries a summary and separate detail, and the outer handlers of the launcher, the worker, their child processes and the maintainer print the summary alone. Messages printed by libxml2 are discarded. The maintainer's status file follows the same rule.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): Failure, caller_notice, report, root_open; [source/src/enroll.hpp](../source/src/enroll.hpp): parse_soap, reject_fault; [source/src/maintain.hpp](../source/src/maintain.hpp): record_failure; [source/tests/tests.cpp](../source/tests/tests.cpp); [source/tests/maintain-integration.cpp](../source/tests/maintain-integration.cpp); [source/TESTING.md](../source/TESTING.md): Audit and Diagnostics Validation. Follow-up: Review the caller-visible summaries again when a failure path is added.

#### [V-222613] APSC-DV-002610 - The application must remove organization-defined software components after updated versions have been installed.

- **Rule ID**: `SV-222613r961677_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002617`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the host's software maintenance. CRAFT's dependencies are OS packages, updated and removed by the OS package manager. CRAFT itself is three executables built from the GitHub source and installed over the previous ones, so no superseded build remains; applying its updates is part of the same host maintenance process.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS; maintained on GitHub); [source/README.md](../source/README.md): Build, Shared Linux installation. Follow-up: None beyond the host's update schedule.

#### [V-222614] APSC-DV-002630 - Security-relevant software updates and patches must be kept up to date.

- **Rule ID**: `SV-222614r1117151_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002605`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the host's software maintenance. CRAFT's dependencies are OS packages, updated and removed by the OS package manager. CRAFT itself is three executables built from the GitHub source and installed over the previous ones, so no superseded build remains; applying its updates is part of the same host maintenance process.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS; maintained on GitHub); [source/README.md](../source/README.md): Build, Shared Linux installation. Follow-up: None beyond the host's update schedule.

#### [V-222619] APSC-DV-002880 - The ISSO must ensure an account management process is implemented, verifying only authorized users can gain access to the application, and individual accounts designated as inactive, suspended, or terminated are promptly removed.

- **Rule ID**: `SV-222619r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002121`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Necessary/noninteractive service accounts and authorized user accounts are governed by the compliant host/AD account inventory and removal/disablement process. CRAFT has no additional built-in password or independent application account database. The documented craft account is required only for privileged modes; source does not create a hidden account bypass.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Host/AD account inventory, inactive-account and service-account restrictions; RHEL-09-411050; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Keep the deployed account inventory within the inherited account-management process. The exact CRAFT CA recipient scope and Key Trust delegation are separate configuration decisions.

#### [V-222621] APSC-DV-002900 - The ISSO must ensure application audit trails are retained for at least 30 months (12 months active + 18 months cold storage) for applications without SAMI data and five years for applications including SAMI data.

- **Rule ID**: `SV-222621r1136913_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000167`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the OS and site audit program by the system owner's determination. CRAFT keeps no audit trail of its own: its AUTHPRIV records are part of the host's audit trail, whose retention, periodic review and violation reporting are those of the host.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: None for CRAFT; the host's retention and review records cover its entries.

#### [V-222622] APSC-DV-002910 - The ISSO must review audit trails periodically based on system documentation recommendations or immediately upon system security events.

- **Rule ID**: `SV-222622r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001872`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the OS and site audit program by the system owner's determination. CRAFT keeps no audit trail of its own: its AUTHPRIV records are part of the host's audit trail, whose retention, periodic review and violation reporting are those of the host.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: None for CRAFT; the host's retention and review records cover its entries.

#### [V-222623] APSC-DV-002920 - The ISSO must report all suspected violations of IA policies in accordance with DoW information system IA procedures.

- **Rule ID**: `SV-222623r1263603_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000149`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the OS and site audit program by the system owner's determination. CRAFT keeps no audit trail of its own: its AUTHPRIV records are part of the host's audit trail, whose retention, periodic review and violation reporting are those of the host.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: None for CRAFT; the host's retention and review records cover its entries.

#### [V-222624] APSC-DV-002930 - The ISSO must ensure active vulnerability testing is performed.

- **Rule ID**: `SV-222624r1051272_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000256`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Fuzz testing is now part of the test procedure and its results are recorded. craft-fuzz, a libFuzzer harness with AddressSanitizer and UndefinedBehaviorSanitizer, covers every parser that takes bytes someone else controls; TESTING.md gives the procedure, settings and the run of 11 October 2026, whose one finding was fixed. The unit, Key Trust and integration suites also pass under both sanitizers. Vulnerability scanning of the installed host is deferred to the OS and enclave scanning program by the system owner's determination; CRAFT has no listener for a network scanner to probe.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (deferred to the OS); [source/tests/fuzz.cpp](../source/tests/fuzz.cpp); [source/tests/fuzz-targets.hpp](../source/tests/fuzz-targets.hpp); [source/TESTING.md](../source/TESTING.md): Fuzz Testing; [source/SECURITY.md](../source/SECURITY.md): Not Claimed. Follow-up: Repeat and record the fuzz run for each release; this closure lapses if a release is not fuzzed.

#### [V-222626] APSC-DV-002960 - The designer must ensure the application does not store configuration and control files in the same directory as user data.

- **Rule ID**: `SV-222626r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000345`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Administrator configuration/trust/service credentials reside under the configured root-controlled configuration directory, while caller data and the credential cache reside in the NSS-resolved home. The private privileged runtime contains acquisition locks/state rather than user configuration. Callers cannot redirect the fixed system configuration directory.
- **Comments / Evidence**: Evidence: [source/src/config.hpp](../source/src/config.hpp): path, config; [source/src/common.hpp](../source/src/common.hpp): caller_home, publish_cache; [source/src/unprivileged.hpp](../source/src/unprivileged.hpp): rate_limit; [source/src/worker.cpp](../source/src/worker.cpp): runtime_directory; [source/README.md](../source/README.md)

#### [V-222627] APSC-DV-002970 - The ISSO must ensure if a DoW STIG or NSA guide is not available, a third-party product will be configured by following available guidance.

- **Rule ID**: `SV-222627r1263605_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000363`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. The third-party components CRAFT uses (Kerberos, OpenSSL, libcurl, libxml2, OpenLDAP and SASL) are OS-distributed packages, configured and hardened under the OS STIG and the system-wide cryptographic policy. CRAFT bundles none of them.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/CMakeLists.txt](../source/CMakeLists.txt); [source/README.md](../source/README.md): Build. Follow-up: None for CRAFT.

#### [V-222628] APSC-DV-002980 - New IP addresses, data services, and associated ports used by the application must be submitted to the appropriate approving authority for the organization, which in turn will be submitted through the DoW Ports, Protocols, and Services Management (DoW PPSM)

- **Rule ID**: `SV-222628r1263608_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000388`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT listens on no port and adds no network service. Its outbound connections use the Kerberos, LDAP and Global Catalog, and HTTPS services of AD DS and AD CS on their standard ports, whose approval and registration belong to those platforms; the host firewall, under the OS STIG, limits what the host may reach.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/config/config.example](../source/config/config.example); [source/config/krb5.conf.example](../source/config/krb5.conf.example). Follow-up: List CRAFT's destinations (KDC, domain controller and Global Catalog, CES) in the host's existing ports-and-protocols record if the site records client flows.

#### [V-222629] APSC-DV-002990 - The application must be registered with the DoW Ports and Protocols Database.

- **Rule ID**: `SV-222629r1263609_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000388`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT listens on no port and adds no network service. Its outbound connections use the Kerberos, LDAP and Global Catalog, and HTTPS services of AD DS and AD CS on their standard ports, whose approval and registration belong to those platforms; the host firewall, under the OS STIG, limits what the host may reach.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/config/config.example](../source/config/config.example); [source/config/krb5.conf.example](../source/config/krb5.conf.example). Follow-up: List CRAFT's destinations (KDC, domain controller and Global Catalog, CES) in the host's existing ports-and-protocols record if the site records client flows.

#### [V-222634] APSC-DV-003030 - The application services and interfaces must be compatible with and ready for IPv6 networks.

- **Rule ID**: `SV-222634r1263611_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002853`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the OS network stack. CRAFT resolves names and connects only through the OS resolver and the Kerberos, LDAP and HTTP libraries, has no address-family-specific code and accepts IPv6 literals in its configured URLs.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/config.hpp](../source/src/config.hpp): plain_url. Follow-up: This assessment did not run CRAFT on an IPv6-only network.

#### [V-222636] APSC-DV-003050 - A contingency plan must exist in accordance with DoW policy based on the application's availability requirements.

- **Rule ID**: `SV-222636r1263613_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000445`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the operating system's backup and recovery configuration by the system owner's determination. CRAFT keeps no data of its own to restore: its configuration, trust files and service credentials are host files under /etc/craft, covered by the host's backup, contingency and recovery procedures, and its source is held off the host in the GitHub repository. Ticket caches and generated keys are short-lived and are issued again, not restored.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (backup and recovery deferred to the OS); [source/README.md](../source/README.md): Shared Linux installation; [source/SECURITY.md](../source/SECURITY.md): User Credential Storage. Follow-up: Rotate the service keytab and agent key if a backup holding them is exposed.

#### [V-222637] APSC-DV-003060 - Recovery procedures and technical system features must exist so recovery is performed in a secure and verifiable manner. The ISSO will document circumstances inhibiting a trusted recovery.

- **Rule ID**: `SV-222637r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000448`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the operating system's backup and recovery configuration by the system owner's determination. CRAFT keeps no data of its own to restore: its configuration, trust files and service credentials are host files under /etc/craft, covered by the host's backup, contingency and recovery procedures, and its source is held off the host in the GitHub repository. Ticket caches and generated keys are short-lived and are issued again, not restored.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (backup and recovery deferred to the OS); [source/README.md](../source/README.md): Shared Linux installation; [source/SECURITY.md](../source/SECURITY.md): User Credential Storage. Follow-up: Rotate the service keytab and agent key if a backup holding them is exposed.

#### [V-222638] APSC-DV-003070 - Data backup must be performed at required intervals in accordance with DoW policy.

- **Rule ID**: `SV-222638r1263615_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000537`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the operating system's backup and recovery configuration by the system owner's determination. CRAFT keeps no data of its own to restore: its configuration, trust files and service credentials are host files under /etc/craft, covered by the host's backup, contingency and recovery procedures, and its source is held off the host in the GitHub repository. Ticket caches and generated keys are short-lived and are issued again, not restored.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (backup and recovery deferred to the OS); [source/README.md](../source/README.md): Shared Linux installation; [source/SECURITY.md](../source/SECURITY.md): User Credential Storage. Follow-up: Rotate the service keytab and agent key if a backup holding them is exposed.

#### [V-222639] APSC-DV-003080 - Back-up copies of the application software or source code must be stored in a fire-rated container or stored separately (offsite).

- **Rule ID**: `SV-222639r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000540`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the operating system's backup and recovery configuration by the system owner's determination. CRAFT keeps no data of its own to restore: its configuration, trust files and service credentials are host files under /etc/craft, covered by the host's backup, contingency and recovery procedures, and its source is held off the host in the GitHub repository. Ticket caches and generated keys are short-lived and are issued again, not restored.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (backup and recovery deferred to the OS); [source/README.md](../source/README.md): Shared Linux installation; [source/SECURITY.md](../source/SECURITY.md): User Credential Storage. Follow-up: Rotate the service keytab and agent key if a backup holding them is exposed.

#### [V-222640] APSC-DV-003090 - Procedures must be in place to assure the appropriate physical and technical protection of the backup and restoration of the application.

- **Rule ID**: `SV-222640r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000540`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to the operating system's backup and recovery configuration by the system owner's determination. CRAFT keeps no data of its own to restore: its configuration, trust files and service credentials are host files under /etc/craft, covered by the host's backup, contingency and recovery procedures, and its source is held off the host in the GitHub repository. Ticket caches and generated keys are short-lived and are issued again, not restored.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (backup and recovery deferred to the OS); [source/README.md](../source/README.md): Shared Linux installation; [source/SECURITY.md](../source/SECURITY.md): User Credential Storage. Follow-up: Rotate the service keytab and agent key if a backup holding them is exposed.

#### [V-222641] APSC-DV-003100 - The application must use encryption to implement key exchange and authenticate endpoints prior to establishing a communication channel for key exchange.

- **Rule ID**: `SV-222641r1263616_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000201`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses the administrator-controlled OS OpenSSL/Kerberos/GSSAPI/TLS libraries and does not select a private provider or disable their system cryptographic policy. Under the supplied platform-compliance assumption those cryptographic modules and policies are validated/approved for protected unclassified exchanges and key exchange. Source adds RSA-size, verified HTTPS and AES-ticket restrictions; a second application-managed FIPS configuration is unnecessary.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-671010, RHEL-09-215105; WN22-SO-000360; approved OS cryptographic modules; [source/CMakeLists.txt](../source/CMakeLists.txt); [source/src/x509.hpp](../source/src/x509.hpp): generate_key; [source/src/enroll.hpp](../source/src/enroll.hpp): wrap_eobo, send_ces; [source/src/directory.hpp](../source/src/directory.hpp): sha256; [source/src/pkinit.hpp](../source/src/pkinit.hpp). Follow-up: Build/deploy against the governed OS libraries and policy. Independently built/bundled modules, component release signing, NSS-specific hash requirements and classified-data requirements remain separate.

#### [V-222642] APSC-DV-003110 - The application must not contain embedded authentication data.

- **Rule ID**: `SV-222642r961863_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-002367`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Runtime credentials come from administrator/caller-provisioned files or freshly generated private keys. The example configuration contains placeholders and ships disabled. Test credentials/certificates are synthetic fixtures, not runtime authentication data embedded in the application.
- **Comments / Evidence**: Evidence: [source/config/config.example](../source/config/config.example); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, get_tgt; [source/tests/tests.cpp](../source/tests/tests.cpp); [source/TESTING.md](../source/TESTING.md). Follow-up: Scan actual release artifacts for secrets before distribution and keep production credentials out of source/build packages.

#### [V-222658] APSC-DV-003240 - All products must be supported by the vendor or the development team.

- **Rule ID**: `SV-222658r961863_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-003376`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: CRAFT is maintained by its development team in its GitHub repository, as the system owner states. Every other component is an OS-vendor-supported package, inherited under the platform assumption.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (maintained on GitHub); [source/README.md](../source/README.md): Build. Follow-up: Decommissioning and update-notification records remain assessed under V-222659, V-222660, V-222669 and V-222670.

#### [V-222661] APSC-DV-003270 - Unnecessary built-in application accounts must be disabled.

- **Rule ID**: `SV-222661r1263620_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003109`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Necessary/noninteractive service accounts and authorized user accounts are governed by the compliant host/AD account inventory and removal/disablement process. CRAFT has no additional built-in password or independent application account database. The documented craft account is required only for privileged modes; source does not create a hidden account bypass.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; Host/AD account inventory, inactive-account and service-account restrictions; RHEL-09-411050; [source/src/common.hpp](../source/src/common.hpp): service_account; [source/README.md](../source/README.md): shared privileged installation. Follow-up: Keep the deployed account inventory within the inherited account-management process. The exact CRAFT CA recipient scope and Key Trust delegation are separate configuration decisions.

#### [V-222663] APSC-DV-003285 - An Application Configuration Guide must be created and included with the application.

- **Rule ID**: `SV-222663r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003124`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: The repository includes configuration/build guides for all three modes, example configuration and Kerberos policy, trust/CRL setup, permissions, authorization boundaries, credential lifecycle and acceptance checks. This provides an Application Configuration Guide. Site-specific enclave, audit, backup/recovery and standardized build inventories still require deployment/process evidence under the corresponding controls.
- **Comments / Evidence**: Evidence: [source/README.md](../source/README.md); [source/config/config.example](../source/config/config.example); [source/config/krb5.conf.example](../source/config/krb5.conf.example); [source/SECURITY.md](../source/SECURITY.md); [source/TESTING.md](../source/TESTING.md); [docs/02-CRAFT-Configuration-and-Validation.pdf](02-CRAFT-Configuration-and-Validation.pdf). Follow-up: Complete and maintain site-specific configuration/environment records before operational use.

#### [V-222667] APSC-DV-003320 - Protections against DoS attacks must be implemented.

- **Rule ID**: `SV-222667r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002386`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Documented DoS mitigations are implemented: finite worker CPU/address-space/deadlines, bounded reads and CES responses, XML restrictions, network timeouts, per-user privileged acquisition locks/intervals and maintainer retry backoff. These address the stated threats; there is no claim of a global quota or architecture-wide DoS immunity.
- **Comments / Evidence**: Evidence: [source/SECURITY.md](../source/SECURITY.md); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/common.hpp](../source/src/common.hpp): read_all; [source/src/unprivileged.hpp](../source/src/unprivileged.hpp): rate_limit; [source/src/enroll.hpp](../source/src/enroll.hpp): receive, parse_soap, send_ces; [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Validate the selected mitigations under deployment load and address the separate DoS testing/low-resource alert review items.

#### [V-222668] APSC-DV-003330 - The system must alert an administrator when low resource conditions are encountered.

- **Rule ID**: `SV-222668r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001274`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Deferred to host resource monitoring. CRAFT is a short-lived client with bounded CPU, memory and run time; low-resource alerting is the host's.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/src/worker.cpp](../source/src/worker.cpp): main. Follow-up: None for CRAFT.

#### [V-222671] APSC-DV-003350 - Connections between the DoW enclave and the Internet or other public or commercial wide area networks must require a DMZ.

- **Rule ID**: `SV-222671r1263624_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001119`
- **Evaluation Status**: **`NotAFinding`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT exposes no listener and is not publicly accessible. The enclave boundary and any DMZ for the services it reaches are those of the network and host.
- **Comments / Evidence**: Evidence: OS compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS). Follow-up: None for CRAFT.

### 5.4. Benchmark exemptions and absent features (127 controls)

#### [V-222387] APSC-DV-000010 - The application must provide a capability to limit the number of logon sessions per user.

- **Rule ID**: `SV-222387r960735_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000054`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not host interactive application logon sessions. Acquisition is a bounded local operation; craft-maintain renews credentials for a watched local job. Neither is an interactive user or administrator session. Issued tickets and downstream service sessions have independent lifetimes.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Reassess if an interactive session interface is added. Apply host and downstream-service session controls separately.

#### [V-222388] APSC-DV-000060 - The application must clear temporary storage and cookies when the session is terminated.

- **Rule ID**: `SV-222388r1043182_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002361`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222389] APSC-DV-000070 - The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed.

- **Rule ID**: `SV-222389r1043182_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002361`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not host interactive application logon sessions. Acquisition is a bounded local operation; craft-maintain renews credentials for a watched local job. Neither is an interactive user or administrator session. Issued tickets and downstream service sessions have independent lifetimes.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Reassess if an interactive session interface is added. Apply host and downstream-service session controls separately.

#### [V-222390] APSC-DV-000080 - The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded.

- **Rule ID**: `SV-222390r1043182_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002361`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not host interactive application logon sessions. Acquisition is a bounded local operation; craft-maintain renews credentials for a watched local job. Neither is an interactive user or administrator session. Issued tickets and downstream service sessions have independent lifetimes.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Reassess if an interactive session interface is added. Apply host and downstream-service session controls separately.

#### [V-222391] APSC-DV-000090 - Applications requiring user access authentication must provide a logoff capability for user initiated communication session.

- **Rule ID**: `SV-222391r961224_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002363`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not host interactive application logon sessions. Acquisition is a bounded local operation; craft-maintain renews credentials for a watched local job. Neither is an interactive user or administrator session. Issued tickets and downstream service sessions have independent lifetimes.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Reassess if an interactive session interface is added. Apply host and downstream-service session controls separately.

#### [V-222392] APSC-DV-000100 - The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

- **Rule ID**: `SV-222392r961227_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-002364`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not host interactive application logon sessions. Acquisition is a bounded local operation; craft-maintain renews credentials for a watched local job. Neither is an interactive user or administrator session. Issued tickets and downstream service sessions have independent lifetimes.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Reassess if an interactive session interface is added. Apply host and downstream-service session controls separately.

#### [V-222398] APSC-DV-000180 - Applications with SOAP messages requiring integrity must include the following message elements:-Message ID-Service Request-Timestamp-SAML Assertion (optionally included in messages) and all elements of the message must be digitally signed.

- **Rule ID**: `SV-222398r960762_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001453`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Not applicable by the system owner's determination, as a constraint of the server protocol. Enrollment Agent speaks MS-WSTEP to the AD CS Certificate Enrollment Web Service, which fixes the message format: a WS-Trust request whose BinarySecurityToken carries the CMS certificate request, secured by the HTTPS binding with Kerberos or client-certificate authentication. That binding defines no envelope signature, timestamp or SAML assertion, and the service would not validate one, so a client has no whole-message signing to supply. Integrity of the exchange rests on verified TLS and on the enrollment agent's CMS signature over the request and requester name, and CRAFT validates the returned certificate before using it. Key Trust and BYOC send no SOAP. The benchmark's own exemption covers applications without SOAP; this disposition instead records that the requirement cannot be implemented against the service.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (AD CS CES protocol constraint); MS-WSTEP; [source/src/enroll.hpp](../source/src/enroll.hpp): wrap_eobo, soap_request, send_ces, parse_response; [source/src/worker.cpp](../source/src/worker.cpp): enroll. Follow-up: Reassess if Microsoft adds message-level protection to CES, or if CRAFT gains another SOAP endpoint.

#### [V-222399] APSC-DV-000190 - Messages protected with WS_Security must use time stamps with creation and expiration times.

- **Rule ID**: `SV-222399r960759_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000068`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Not applicable by the system owner's determination, as a constraint of the server protocol. CRAFT does not use WS-Security or SAML to protect messages. Its one SOAP exchange, MS-WSTEP with the AD CS Certificate Enrollment Web Service in Enrollment Agent, uses the BinarySecurityToken element only as the container that MS-WSTEP prescribes for the CMS certificate request and the returned certificate. The binding defines no security header, timestamp, validity period or assertion, and the service would not process one. The exchange is protected by verified TLS and the enrollment agent's CMS signature. Key Trust and BYOC send no SOAP.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (AD CS CES protocol constraint); MS-WSTEP; [source/src/enroll.hpp](../source/src/enroll.hpp): soap_request, send_ces, parse_response. Follow-up: Reassess with V-222398 if the CES protocol changes.

#### [V-222400] APSC-DV-000200 - Validity periods must be verified on all application messages using WS-Security or SAML assertions.

- **Rule ID**: `SV-222400r960759_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000068`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Not applicable by the system owner's determination, as a constraint of the server protocol. CRAFT does not use WS-Security or SAML to protect messages. Its one SOAP exchange, MS-WSTEP with the AD CS Certificate Enrollment Web Service in Enrollment Agent, uses the BinarySecurityToken element only as the container that MS-WSTEP prescribes for the CMS certificate request and the returned certificate. The binding defines no security header, timestamp, validity period or assertion, and the service would not process one. The exchange is protected by verified TLS and the enrollment agent's CMS signature. Key Trust and BYOC send no SOAP.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (AD CS CES protocol constraint); MS-WSTEP; [source/src/enroll.hpp](../source/src/enroll.hpp): soap_request, send_ces, parse_response. Follow-up: Reassess with V-222398 if the CES protocol changes.

#### [V-222401] APSC-DV-000210 - The application must ensure each unique asserting party provides unique assertion ID references for each SAML assertion.

- **Rule ID**: `SV-222401r960759_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000068`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not issue, consume or validate SAML assertions, SubjectConfirmation/Conditions elements, AuthnStatement or SAML SessionIndex values. The Enrollment Agent PKCS7 enrollment token is not a SAML assertion.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp): soap_request, parse_response. Follow-up: Reassess if a SAML identity-provider or relying-party integration is introduced.

#### [V-222402] APSC-DV-000220 - The application must ensure encrypted assertions, or equivalent confidentiality protections are used when assertion data is passed through an intermediary, and confidentiality of the assertion data is required when passing through the intermediary.

- **Rule ID**: `SV-222402r960759_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000068`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Not applicable by the system owner's determination, as a constraint of the server protocol. CRAFT does not use WS-Security or SAML to protect messages. Its one SOAP exchange, MS-WSTEP with the AD CS Certificate Enrollment Web Service in Enrollment Agent, uses the BinarySecurityToken element only as the container that MS-WSTEP prescribes for the CMS certificate request and the returned certificate. The binding defines no security header, timestamp, validity period or assertion, and the service would not process one. The exchange is protected by verified TLS and the enrollment agent's CMS signature. Key Trust and BYOC send no SOAP.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (AD CS CES protocol constraint); MS-WSTEP; [source/src/enroll.hpp](../source/src/enroll.hpp): soap_request, send_ces, parse_response. Follow-up: Reassess with V-222398 if the CES protocol changes.

#### [V-222403] APSC-DV-000230 - The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML assertion.

- **Rule ID**: `SV-222403r960759_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000068`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not issue, consume or validate SAML assertions, SubjectConfirmation/Conditions elements, AuthnStatement or SAML SessionIndex values. The Enrollment Agent PKCS7 enrollment token is not a SAML assertion.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp): soap_request, parse_response. Follow-up: Reassess if a SAML identity-provider or relying-party integration is introduced.

#### [V-222404] APSC-DV-000240 - The application must use both the NotBefore and NotOnOrAfter elements or OneTimeUse element when using the Conditions element in a SAML assertion.

- **Rule ID**: `SV-222404r960759_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000068`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not issue, consume or validate SAML assertions, SubjectConfirmation/Conditions elements, AuthnStatement or SAML SessionIndex values. The Enrollment Agent PKCS7 enrollment token is not a SAML assertion.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp): soap_request, parse_response. Follow-up: Reassess if a SAML identity-provider or relying-party integration is introduced.

#### [V-222405] APSC-DV-000250 - The application must ensure if a OneTimeUse element is used in an assertion, there is only one of the same used in the Conditions element portion of an assertion.

- **Rule ID**: `SV-222405r960759_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000068`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not issue, consume or validate SAML assertions, SubjectConfirmation/Conditions elements, AuthnStatement or SAML SessionIndex values. The Enrollment Agent PKCS7 enrollment token is not a SAML assertion.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp): soap_request, parse_response. Follow-up: Reassess if a SAML identity-provider or relying-party integration is introduced.

#### [V-222406] APSC-DV-000260 - The application must ensure messages are encrypted when the SessionIndex is tied to privacy data.

- **Rule ID**: `SV-222406r960759_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000068`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not issue, consume or validate SAML assertions, SubjectConfirmation/Conditions elements, AuthnStatement or SAML SessionIndex values. The Enrollment Agent PKCS7 enrollment token is not a SAML assertion.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp): soap_request, parse_response. Follow-up: Reassess if a SAML identity-provider or relying-party integration is introduced.

#### [V-222408] APSC-DV-000290 - Shared/group account credentials must be terminated when members leave the group.

- **Rule ID**: `SV-222408r1015683_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004045`, `CCI-002142`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: The reference workflow does not offer shared/group user logons. Each invocation identifies an individual real UID and requests that caller's fixed Kerberos principal. The dedicated craft/service principal is a machine credential used by the isolated worker, not a shared user logon offered to callers.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/README.md](../source/README.md). Follow-up: Reassess if shared human accounts are authorized. Service credential custody and administrator access remain deployment review items.

#### [V-222411] APSC-DV-000320 - The application must automatically disable accounts after a 35 day period of account inactivity.

- **Rule ID**: `SV-222411r960774_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000017`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222413] APSC-DV-000340 - The application must automatically audit account creation.

- **Rule ID**: `SV-222413r960777_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000018`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222414] APSC-DV-000350 - The application must automatically audit account modification.

- **Rule ID**: `SV-222414r960780_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001403`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222415] APSC-DV-000360 - The application must automatically audit account disabling actions.

- **Rule ID**: `SV-222415r960783_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001404`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222416] APSC-DV-000370 - The application must automatically audit account removal actions.

- **Rule ID**: `SV-222416r960786_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001405`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222417] APSC-DV-000380 - The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are created.

- **Rule ID**: `SV-222417r1015684_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000015`, `CCI-001683`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222418] APSC-DV-000390 - The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are modified.

- **Rule ID**: `SV-222418r1015685_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000015`, `CCI-001684`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222419] APSC-DV-000400 - The application must notify system administrators (SAs) and information system security officers (ISSOs) of account disabling actions.

- **Rule ID**: `SV-222419r1015686_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000015`, `CCI-001685`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222420] APSC-DV-000410 - The application must notify system administrators (SAs) and information system security officers (ISSOs) of account removal actions.

- **Rule ID**: `SV-222420r1015687_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000015`, `CCI-001686`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222421] APSC-DV-000420 - The application must automatically audit account enabling actions.

- **Rule ID**: `SV-222421r961290_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002130`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222422] APSC-DV-000430 - The application must notify system administrators (SAs) and information system security officers (ISSOs) of account enabling actions.

- **Rule ID**: `SV-222422r1015688_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000015`, `CCI-002132`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222427] APSC-DV-000480 - The application must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.

- **Rule ID**: `SV-222427r1117168_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001368`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT provides no data-flow control capability, which the official check exempts. Information flow within and between systems is enforced by the host firewall and the network, under the OS and enclave controls to which this is deferred.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/SECURITY.md](../source/SECURITY.md). Follow-up: None for CRAFT.

#### [V-222428] APSC-DV-000490 - The application must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.

- **Rule ID**: `SV-222428r1117169_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001414`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT provides no data-flow control capability, which the official check exempts. Information flow within and between systems is enforced by the host firewall and the network, under the OS and enclave controls to which this is deferred.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (deferred to the OS); [source/SECURITY.md](../source/SECURITY.md). Follow-up: None for CRAFT.

#### [V-222434] APSC-DV-000550 - The application must display the Standard Mandatory DoW Notice and Consent Banner before granting access to the application.

- **Rule ID**: `SV-222434r1263534_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000048`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no interactive application logon UI. The fixed-argument acquisition helper and watched-job maintainer do not display or solicit interactive consent. The benchmark explicitly excludes applications without an interactive UI.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.cpp](../source/src/maintain.cpp). Follow-up: Host console/SSH banner requirements are assessed separately. Reassess if an interactive application UI is added.

#### [V-222435] APSC-DV-000560 - The application must retain the Standard Mandatory DoW Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

- **Rule ID**: `SV-222435r1263537_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000050`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no interactive application logon UI. The fixed-argument acquisition helper and watched-job maintainer do not display or solicit interactive consent. The benchmark explicitly excludes applications without an interactive UI.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.cpp](../source/src/maintain.cpp). Follow-up: Host console/SSH banner requirements are assessed separately. Reassess if an interactive application UI is added.

#### [V-222436] APSC-DV-000570 - The publicly accessible application must display the Standard Mandatory DoW Notice and Consent Banner before granting access to the application.

- **Rule ID**: `SV-222436r1263540_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-001384`, `CCI-001385`, `CCI-001386`, `CCI-001387`, `CCI-001388`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT exposes no publicly accessible application interface or listening service. It is invoked locally and makes outbound credential-acquisition connections. The public-application banner check is outside this architecture.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/README.md](../source/README.md). Follow-up: Reassess if a public service or UI is added; externally operated CES/KDC interfaces are assessed separately.

#### [V-222437] APSC-DV-000580 - The application must display the time and date of the users last successful logon.

- **Rule ID**: `SV-222437r987626_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000052`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not host interactive application logon sessions. Acquisition is a bounded local operation; craft-maintain renews credentials for a watched local job. Neither is an interactive user or administrator session. Issued tickets and downstream service sessions have independent lifetimes.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Reassess if an interactive session interface is added. Apply host and downstream-service session controls separately.

#### [V-222439] APSC-DV-000600 - For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail.

- **Rule ID**: `SV-222439r960873_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000174`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT emits events to host syslog but does not aggregate audit records from other components. The check explicitly excludes applications that do not provide log aggregation services.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve

#### [V-222441] APSC-DV-000620 - The application must provide audit record generation capability for the creation of session IDs.

- **Rule ID**: `SV-222441r960879_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000169`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222442] APSC-DV-000630 - The application must provide audit record generation capability for the destruction of session IDs.

- **Rule ID**: `SV-222442r960879_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000169`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222443] APSC-DV-000640 - The application must provide audit record generation capability for the renewal of session IDs.

- **Rule ID**: `SV-222443r960879_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000169`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222445] APSC-DV-000660 - The application must provide audit record generation capability for session timeouts.

- **Rule ID**: `SV-222445r1263543_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000169`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222447] APSC-DV-000680 - The application must provide audit record generation capability for HTTP headers including User-Agent, Referer, GET, and POST.

- **Rule ID**: `SV-222447r1263544_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000169`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not operate an HTTP server receiving User-Agent, Referer, GET or POST requests from application users. Enrollment Agent sends its own fixed SOAP POST as a client; it does not accept HTTP application access.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp): send_ces; [source/src/worker.cpp](../source/src/worker.cpp). Follow-up: Assess request-header auditing at the independently operated CES/web server.

#### [V-222448] APSC-DV-000690 - The application must provide audit record generation capability for connecting system IP addresses.

- **Rule ID**: `SV-222448r960879_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000169`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not listen for remote application-client connections. There are no connecting client-system IP addresses to audit at a CRAFT server. Its outbound destinations are covered by V-222470.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp)

#### [V-222450] APSC-DV-000710 - The application must generate audit records when successful/unsuccessful attempts to grant privileges occur.

- **Rule ID**: `SV-222450r960885_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not expose application role/security-level creation, assignment, modification, deletion or user role switching. It requests the caller's existing identity and does not grant that AD account new authorization privileges. OS credential transitions and delegated credential operations still require auditing under the applicable privileged-function and security-object controls.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp). Follow-up: Reassess if application-managed roles or privilege-management features are added.

#### [V-222452] APSC-DV-000730 - The application must generate audit records when successful/unsuccessful attempts to access security levels occur.

- **Rule ID**: `SV-222452r961794_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not expose application role/security-level creation, assignment, modification, deletion or user role switching. It requests the caller's existing identity and does not grant that AD account new authorization privileges. OS credential transitions and delegated credential operations still require auditing under the applicable privileged-function and security-object controls.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp). Follow-up: Reassess if application-managed roles or privilege-management features are added.

#### [V-222454] APSC-DV-000750 - The application must generate audit records when successful/unsuccessful attempts to modify privileges occur.

- **Rule ID**: `SV-222454r961800_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not expose application role/security-level creation, assignment, modification, deletion or user role switching. It requests the caller's existing identity and does not grant that AD account new authorization privileges. OS credential transitions and delegated credential operations still require auditing under the applicable privileged-function and security-object controls.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp). Follow-up: Reassess if application-managed roles or privilege-management features are added.

#### [V-222456] APSC-DV-000770 - The application must generate audit records when successful/unsuccessful attempts to modify security levels occur.

- **Rule ID**: `SV-222456r961806_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not expose application role/security-level creation, assignment, modification, deletion or user role switching. It requests the caller's existing identity and does not grant that AD account new authorization privileges. OS credential transitions and delegated credential operations still require auditing under the applicable privileged-function and security-object controls.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp). Follow-up: Reassess if application-managed roles or privilege-management features are added.

#### [V-222458] APSC-DV-000790 - The application must generate audit records when successful/unsuccessful attempts to delete privileges occur.

- **Rule ID**: `SV-222458r961812_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not expose application role/security-level creation, assignment, modification, deletion or user role switching. It requests the caller's existing identity and does not grant that AD account new authorization privileges. OS credential transitions and delegated credential operations still require auditing under the applicable privileged-function and security-object controls.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp). Follow-up: Reassess if application-managed roles or privilege-management features are added.

#### [V-222459] APSC-DV-000800 - The application must generate audit records when successful/unsuccessful attempts to delete security levels occur.

- **Rule ID**: `SV-222459r961815_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not expose application role/security-level creation, assignment, modification, deletion or user role switching. It requests the caller's existing identity and does not grant that AD account new authorization privileges. OS credential transitions and delegated credential operations still require auditing under the applicable privileged-function and security-object controls.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp). Follow-up: Reassess if application-managed roles or privilege-management features are added.

#### [V-222460] APSC-DV-000810 - The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur.

- **Rule ID**: `SV-222460r961818_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no relational database, SQL query interface, database security objects or production-to-test database exports. Active Directory access uses LDAP and is evaluated under directory/credential controls.
- **Comments / Evidence**: Evidence: [source/src/directory.hpp](../source/src/directory.hpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/README.md](../source/README.md)

#### [V-222464] APSC-DV-000850 - The application must generate audit records showing starting and ending time for user access to the system.

- **Rule ID**: `SV-222464r961830_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not host interactive application logon sessions. Acquisition is a bounded local operation; craft-maintain renews credentials for a watched local job. Neither is an interactive user or administrator session. Issued tickets and downstream service sessions have independent lifetimes.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Reassess if an interactive session interface is added. Apply host and downstream-service session controls separately.

#### [V-222466] APSC-DV-000870 - The application must generate audit records for all direct access to the information system.

- **Rule ID**: `SV-222466r961839_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT provides no command shell, remote system administration interface, file-transfer endpoint or other direct interactive access to the information system. It publishes a credential cache; downstream clients perform and audit their own direct accesses.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/README.md](../source/README.md). Follow-up: Reassess if direct system-access functionality is introduced.

#### [V-222467] APSC-DV-000880 - The application must generate audit records for all account creations, modifications, disabling, and termination events.

- **Rule ID**: `SV-222467r961842_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. CRAFT uses existing host/NSS and AD identities and has no application account-management store. The official check explicitly exempts use of a STIG-compliant enterprise account-management capability; that prerequisite is satisfied by the assessment assumption. Account lifecycle, account-event auditing and associated notification obligations are assigned to that enterprise capability.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; ASD enterprise-account-management exemption; RHEL-09-411050; RHEL-09-654225 through RHEL-09-654245 equivalent account-file auditing; WN22-AU-000090 through WN22-AU-000120; [source/src/common.hpp](../source/src/common.hpp): lookup_uid, service_account; [source/src/directory.hpp](../source/src/directory.hpp): directory_lookup; [source/README.md](../source/README.md); [source/SECURITY.md](../source/SECURITY.md). Follow-up: Maintain the inherited enterprise identity boundary. Reassess if CRAFT introduces an independent account store or a local authentication path that bypasses enterprise identity management.

#### [V-222478] APSC-DV-001030 - The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.

- **Rule ID**: `SV-222478r960909_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000135`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no privileged command interpreter or application management console and offers no shared human logon. The public acquisition command accepts no arguments. This command/group-account recording feature is absent; privileged operation coverage is assessed separately under V-222431 and V-222463.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp)

#### [V-222479] APSC-DV-001040 - The application must implement transaction recovery logs when transaction based.

- **Rule ID**: `SV-222479r960909_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000135`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is not a transaction-processing application with database/business transaction recovery. Key Trust uses single-value LDAP updates and an independent cleanup guardian, not an application transaction-log recovery engine. That credential-cleanup risk remains in scope for failure/recovery review.
- **Comments / Evidence**: Evidence: [source/src/directory.hpp](../source/src/directory.hpp): modify_key_credential, KeyCredentialGuard; [source/SECURITY.md](../source/SECURITY.md)

#### [V-222480] APSC-DV-001050 - The application must provide centralized management and configuration of the content to be captured in audit records generated by all application components.

- **Rule ID**: `SV-222480r985972_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000154`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222481] APSC-DV-001070 - The application must off-load audit records onto a different system or media than the system being audited.

- **Rule ID**: `SV-222481r961395_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001851`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. The compliant host forwards its audit/log records to the centralized logging system. CRAFT uses the host AUTHPRIV path. The ASD check explicitly exempts applications configured to use centralized logging; a separate CRAFT offload scheduler is not required.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve; [source/SECURITY.md](../source/SECURITY.md). Follow-up: Keep CRAFT AUTHPRIV records in the inherited forwarding policy. Application pre-ingestion delivery failure remains assessed under V-222486.

#### [V-222487] APSC-DV-001130 - The application must provide the capability to centrally review and analyze audit records from multiple components within the system.

- **Rule ID**: `SV-222487r960918_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000154`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222488] APSC-DV-001140 - The application must provide the capability to filter audit records for events of interest based upon organization-defined criteria.

- **Rule ID**: `SV-222488r960924_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000158`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222489] APSC-DV-001150 - The application must provide an audit reduction capability that supports on-demand reporting requirements.

- **Rule ID**: `SV-222489r961056_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001876`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222490] APSC-DV-001160 - The application must provide an audit reduction capability that supports on-demand audit review and analysis.

- **Rule ID**: `SV-222490r961413_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001875`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222491] APSC-DV-001170 - The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents.

- **Rule ID**: `SV-222491r1263545_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001877`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222492] APSC-DV-001180 - The application must provide a report generation capability that supports on-demand audit review and analysis.

- **Rule ID**: `SV-222492r961419_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001878`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222493] APSC-DV-001190 - The application must provide a report generation capability that supports on-demand reporting requirements.

- **Rule ID**: `SV-222493r961422_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001879`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222494] APSC-DV-001200 - The application must provide a report generation capability that supports after-the-fact investigations of security incidents.

- **Rule ID**: `SV-222494r1263546_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001880`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222495] APSC-DV-001210 - The application must provide an audit reduction capability that does not alter original content or time ordering of audit records.

- **Rule ID**: `SV-222495r961428_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001881`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT writes its records to the host logging service and keeps no log store of its own; the compliant host forwards them to the centralized logging system, which provides this capability. The official check exempts applications that use such a system.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); RHEL-09-652055; ASD centralized-logging exemption; [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md): Audit Records and Diagnostics. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222496] APSC-DV-001220 - The application must provide a report generation capability that does not alter original content or time ordering of audit records.

- **Rule ID**: `SV-222496r961431_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001882`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide a separate audit viewer, query/manipulation tool or report-generation facility. The benchmark explicitly exempts applications without the corresponding tool/capability. Host and centralized audit tools require their own assessment.
- **Comments / Evidence**: Evidence: [source/CMakeLists.txt](../source/CMakeLists.txt); [source/src/directory.hpp](../source/src/directory.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp)

#### [V-222499] APSC-DV-001270 - The application must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.

- **Rule ID**: `SV-222499r961446_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001889`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: The application relies on the underlying OS syslog infrastructure for audit timestamping rather than maintaining an application timestamping/synchronization engine. This matches the check's explicit underlying-OS exemption; it does not establish host clock accuracy.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): audit; [source/src/maintain.hpp](../source/src/maintain.hpp): serve. Follow-up: Verify host/collector time synchronization and record granularity in the operating-system assessment.

#### [V-222503] APSC-DV-001310 - The application must protect audit tools from unauthorized access.

- **Rule ID**: `SV-222503r960939_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001493`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide a separate audit viewer, query/manipulation tool or report-generation facility. The benchmark explicitly exempts applications without the corresponding tool/capability. Host and centralized audit tools require their own assessment.
- **Comments / Evidence**: Evidence: [source/CMakeLists.txt](../source/CMakeLists.txt); [source/src/directory.hpp](../source/src/directory.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp)

#### [V-222504] APSC-DV-001320 - The application must protect audit tools from unauthorized modification.

- **Rule ID**: `SV-222504r960942_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001494`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide a separate audit viewer, query/manipulation tool or report-generation facility. The benchmark explicitly exempts applications without the corresponding tool/capability. Host and centralized audit tools require their own assessment.
- **Comments / Evidence**: Evidence: [source/CMakeLists.txt](../source/CMakeLists.txt); [source/src/directory.hpp](../source/src/directory.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp)

#### [V-222505] APSC-DV-001330 - The application must protect audit tools from unauthorized deletion.

- **Rule ID**: `SV-222505r960945_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001495`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide a separate audit viewer, query/manipulation tool or report-generation facility. The benchmark explicitly exempts applications without the corresponding tool/capability. Host and centralized audit tools require their own assessment.
- **Comments / Evidence**: Evidence: [source/CMakeLists.txt](../source/CMakeLists.txt); [source/src/directory.hpp](../source/src/directory.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp)

#### [V-222506] APSC-DV-001340 - The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.

- **Rule ID**: `SV-222506r960948_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001348`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no built-in facility for backing up its own audit records. The check explicitly exempts this case. Enterprise backup and long-term audit retention remain separate review items.
- **Comments / Evidence**: Evidence: [source/src/common.hpp](../source/src/common.hpp): audit; [source/README.md](../source/README.md). Follow-up: Apply host/enterprise backup and V-222621 retention requirements to the retained CRAFT events.

#### [V-222507] APSC-DV-001350 - The application must use cryptographic mechanisms to protect the integrity of audit information.

- **Rule ID**: `SV-222507r960951_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001350`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Inherited under the assessment assumption that the underlying operating systems and Active Directory satisfy their applicable STIG controls. Logging is deferred to the OS by the system owner's determination. CRAFT holds no audit information of its own to seal: its records go to the host logging service, and their integrity is protected by the host audit protections and the centralized audit solution. The official check exempts applications that use such a solution.
- **Comments / Evidence**: Evidence: OS/AD compliance assumption; System-owner determination, 11 October 2026 (logging deferred to the OS); ASD centralized-audit exemption; [source/src/common.hpp](../source/src/common.hpp): audit. Follow-up: Keep the AUTHPRIV facility within the host's forwarding policy.

#### [V-222508] APSC-DV-001360 - Application audit tools must be cryptographically hashed.

- **Rule ID**: `SV-222508r961206_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001496`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide a separate audit viewer, query/manipulation tool or report-generation facility. The benchmark explicitly exempts applications without the corresponding tool/capability. Host and centralized audit tools require their own assessment.
- **Comments / Evidence**: Evidence: [source/CMakeLists.txt](../source/CMakeLists.txt); [source/src/directory.hpp](../source/src/directory.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp)

#### [V-222509] APSC-DV-001370 - The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash value.

- **Rule ID**: `SV-222509r961206_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001496`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide a separate audit viewer, query/manipulation tool or report-generation facility. The benchmark explicitly exempts applications without the corresponding tool/capability. Host and centralized audit tools require their own assessment.
- **Comments / Evidence**: Evidence: [source/CMakeLists.txt](../source/CMakeLists.txt); [source/src/directory.hpp](../source/src/directory.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp)

#### [V-222510] APSC-DV-001390 - The application must prohibit user installation of software without explicit privileged status.

- **Rule ID**: `SV-222510r1015689_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003980`, `CCI-001812`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is not a software installer, configuration-management product or program-whitelisting manager. It exposes no interface for users to install application modules, extensions or managed programs. The relevant check explicitly excludes products without that capability.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/CMakeLists.txt](../source/CMakeLists.txt)

#### [V-222513] APSC-DV-001430 - The application must have the capability to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.

- **Rule ID**: `SV-222513r1263547_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003992`, `CCI-001749`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Not applicable by the system owner's determination: CRAFT is maintained and distributed as source in its GitHub repository and ships no binaries, packages, patches or signed release artifacts. There is no vendor package whose signature or published hash an installer could verify; each site builds from a chosen commit, which Git identifies by a cryptographic hash, and installs it under its own host software-management controls. Verification of the OS packages CRAFT depends on is inherited from the OS.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (source-only distribution; signed releases not applicable); [source/README.md](../source/README.md): Build; [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Reassess if binaries or packages are ever published.

#### [V-222517] APSC-DV-001490 - The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.

- **Rule ID**: `SV-222517r961479_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001774`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is not a software installer, configuration-management product or program-whitelisting manager. It exposes no interface for users to install application modules, extensions or managed programs. The relevant check explicitly excludes products without that capability.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/CMakeLists.txt](../source/CMakeLists.txt)

#### [V-222520] APSC-DV-001520 - The application must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.

- **Rule ID**: `SV-222520r1263548_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004895`, `CCI-002038`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no user role-switch or privilege-escalation interface of the kind exercised by this check. Callers cannot select another AD identity or administrator role. The setuid launcher delegates a fixed credential task; it does not grant the caller an application administrator session.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp). Follow-up: Reassess if user-selectable application roles or escalation are introduced.

#### [V-222521] APSC-DV-001530 - The application must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

- **Rule ID**: `SV-222521r985974_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002038`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is a local credential client and does not accept connections from remote device/service consumers, maintain device identities or manage gateway/device reauthentication. Authenticating its outbound directory/CES/KDC peers is distinct from providing a service to managed endpoint devices.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/directory.hpp](../source/src/directory.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp). Follow-up: Assess device/service-consumer controls at any independently operated service provider.

#### [V-222529] APSC-DV-001610 - The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.

- **Rule ID**: `SV-222529r1015695_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004045`, `CCI-000770`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: The reference workflow does not offer shared/group user logons. Each invocation identifies an individual real UID and requests that caller's fixed Kerberos principal. The dedicated craft/service principal is a machine credential used by the isolated worker, not a shared user logon offered to callers.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/README.md](../source/README.md). Follow-up: Reassess if shared human accounts are authorized. Service credential custody and administrator access remain deployment review items.

#### [V-222533] APSC-DV-001650 - The application must authenticate all network connected endpoint devices before establishing any connection.

- **Rule ID**: `SV-222533r961503_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001958`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is a local credential client and does not accept connections from remote device/service consumers, maintain device identities or manage gateway/device reauthentication. Authenticating its outbound directory/CES/KDC peers is distinct from providing a service to managed endpoint devices.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/directory.hpp](../source/src/directory.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp). Follow-up: Assess device/service-consumer controls at any independently operated service provider.

#### [V-222535] APSC-DV-001670 - The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.

- **Rule ID**: `SV-222535r1263562_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003627`, `CCI-000795`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is a local credential client and does not accept connections from remote device/service consumers, maintain device identities or manage gateway/device reauthentication. Authenticating its outbound directory/CES/KDC peers is distinct from providing a service to managed endpoint devices.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/src/directory.hpp](../source/src/directory.hpp); [source/src/enroll.hpp](../source/src/enroll.hpp). Follow-up: Assess device/service-consumer controls at any independently operated service provider.

#### [V-222536] APSC-DV-001680 - The application must enforce a minimum 15-character password length.

- **Rule ID**: `SV-222536r1263563_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-004066`, `CCI-000205`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222537] APSC-DV-001690 - The application must enforce password complexity by requiring that at least one uppercase character be used.

- **Rule ID**: `SV-222537r1263564_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004066`, `CCI-000192`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222538] APSC-DV-001700 - The application must enforce password complexity by requiring that at least one lowercase character be used.

- **Rule ID**: `SV-222538r1263565_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004066`, `CCI-000193`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222539] APSC-DV-001710 - The application must enforce password complexity by requiring that at least one numeric character be used.

- **Rule ID**: `SV-222539r1263566_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004066`, `CCI-000194`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222540] APSC-DV-001720 - The application must enforce password complexity by requiring that at least one special character be used.

- **Rule ID**: `SV-222540r1263567_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004066`, `CCI-001619`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222541] APSC-DV-001730 - The application must require the change of at least eight of the total number of characters when passwords are changed.

- **Rule ID**: `SV-222541r1263568_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004066`, `CCI-000195`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222542] APSC-DV-001740 - The application must only store cryptographic representations of passwords.

- **Rule ID**: `SV-222542r1263569_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-004062`, `CCI-000196`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222543] APSC-DV-001750 - The application must transmit only cryptographically-protected passwords.

- **Rule ID**: `SV-222543r1263570_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000197`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222544] APSC-DV-001760 - The application must enforce 24 hours/1 day as the minimum password lifetime.

- **Rule ID**: `SV-222544r1263571_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004066`, `CCI-000198`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222545] APSC-DV-001770 - The application must enforce a 180-day maximum password lifetime restriction.

- **Rule ID**: `SV-222545r1263524_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004066`, `CCI-000199`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems. The current benchmark maximum password age is 180 days; it does not apply to this passwordless application interface.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222546] APSC-DV-001780 - The application must prohibit password reuse for a minimum of five generations.

- **Rule ID**: `SV-222546r1263572_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004061`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222547] APSC-DV-001790 - The application must allow the use of a temporary password for system logons with an immediate change to a permanent password.

- **Rule ID**: `SV-222547r1263573_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000366`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222548] APSC-DV-001795 - The application password must not be changeable by users other than the administrator or the user with which the password is associated.

- **Rule ID**: `SV-222548r1263575_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000184`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222554] APSC-DV-001850 - The application must not display passwords/PINs as clear text.

- **Rule ID**: `SV-222554r961047_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000206`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222555] APSC-DV-001860 - The application must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

- **Rule ID**: `SV-222555r961050_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-000803`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide a PIN/password login or authenticated user interface to a cryptographic module. Its software-library API calls and file-key handling are not such a module-authentication facility. The check explicitly exempts applications that do not provide authenticated module access; this says nothing about FIPS validation of the libraries.
- **Comments / Evidence**: Evidence: [source/src/x509.hpp](../source/src/x509.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp): refuse_prompt; [source/SECURITY.md](../source/SECURITY.md)

#### [V-222561] APSC-DV-001930 - Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions for organization-defined auditable events.

- **Rule ID**: `SV-222561r961548_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002884`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide non-local maintenance, remote diagnostic access or a remote administration session. craft-maintain is a locally started credential-renewal process watching a local PID, not a remote maintenance service. Its name does not make these remote-maintenance controls applicable.
- **Comments / Evidence**: Evidence: [source/src/maintain.cpp](../source/src/maintain.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/README.md](../source/README.md). Follow-up: Assess SSH and other host remote-maintenance facilities separately.

#### [V-222562] APSC-DV-001940 - Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the integrity of non-local maintenance and diagnostic communications.

- **Rule ID**: `SV-222562r961554_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002890`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide non-local maintenance, remote diagnostic access or a remote administration session. craft-maintain is a locally started credential-renewal process watching a local PID, not a remote maintenance service. Its name does not make these remote-maintenance controls applicable.
- **Comments / Evidence**: Evidence: [source/src/maintain.cpp](../source/src/maintain.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/README.md](../source/README.md). Follow-up: Assess SSH and other host remote-maintenance facilities separately.

#### [V-222563] APSC-DV-001950 - Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the confidentiality of non-local maintenance and diagnostic communications.

- **Rule ID**: `SV-222563r961557_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-003123`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide non-local maintenance, remote diagnostic access or a remote administration session. craft-maintain is a locally started credential-renewal process watching a local PID, not a remote maintenance service. Its name does not make these remote-maintenance controls applicable.
- **Comments / Evidence**: Evidence: [source/src/maintain.cpp](../source/src/maintain.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/README.md](../source/README.md). Follow-up: Assess SSH and other host remote-maintenance facilities separately.

#### [V-222564] APSC-DV-001960 - Applications used for non-local maintenance sessions must verify remote disconnection at the termination of non-local maintenance and diagnostic sessions.

- **Rule ID**: `SV-222564r961560_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002891`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide non-local maintenance, remote diagnostic access or a remote administration session. craft-maintain is a locally started credential-renewal process watching a local PID, not a remote maintenance service. Its name does not make these remote-maintenance controls applicable.
- **Comments / Evidence**: Evidence: [source/src/maintain.cpp](../source/src/maintain.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/README.md](../source/README.md). Follow-up: Assess SSH and other host remote-maintenance facilities separately.

#### [V-222565] APSC-DV-001970 - The application must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.

- **Rule ID**: `SV-222565r961062_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000877`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide non-local maintenance, remote diagnostic access or a remote administration session. craft-maintain is a locally started credential-renewal process watching a local PID, not a remote maintenance service. Its name does not make these remote-maintenance controls applicable.
- **Comments / Evidence**: Evidence: [source/src/maintain.cpp](../source/src/maintain.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/README.md](../source/README.md). Follow-up: Assess SSH and other host remote-maintenance facilities separately.

#### [V-222566] APSC-DV-001980 - The application must terminate all sessions and network connections when nonlocal maintenance is completed.

- **Rule ID**: `SV-222566r985978_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-004190`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide non-local maintenance, remote diagnostic access or a remote administration session. craft-maintain is a locally started credential-renewal process watching a local PID, not a remote maintenance service. Its name does not make these remote-maintenance controls applicable.
- **Comments / Evidence**: Evidence: [source/src/maintain.cpp](../source/src/maintain.cpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/README.md](../source/README.md). Follow-up: Assess SSH and other host remote-maintenance facilities separately.

#### [V-222570] APSC-DV-002020 - The application must utilize FIPS-validated cryptographic modules when signing application components.

- **Rule ID**: `SV-222570r1263585_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002450`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Not applicable by the system owner's determination: CRAFT is maintained and distributed as source in its GitHub repository and ships no binaries, packages, patches or signed release artifacts. There is no vendor package whose signature or published hash an installer could verify; each site builds from a chosen commit, which Git identifies by a cryptographic hash, and installs it under its own host software-management controls. Verification of the OS packages CRAFT depends on is inherited from the OS.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (source-only distribution; signed releases not applicable); [source/README.md](../source/README.md): Build; [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Reassess if binaries or packages are ever published.

#### [V-222573] APSC-DV-002050 - Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.

- **Rule ID**: `SV-222573r1117181_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002450`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not issue, consume or validate SAML assertions, SubjectConfirmation/Conditions elements, AuthnStatement or SAML SessionIndex values. The Enrollment Agent PKCS7 enrollment token is not a SAML assertion.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp): soap_request, parse_response. Follow-up: Reassess if a SAML identity-provider or relying-party integration is introduced.

#### [V-222575] APSC-DV-002210 - The application must set the HTTPOnly flag on session cookies.

- **Rule ID**: `SV-222575r1043178_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001184`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222576] APSC-DV-002220 - The application must set the secure flag on session cookies.

- **Rule ID**: `SV-222576r1043178_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001184`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222577] APSC-DV-002230 - The application must not expose session IDs.

- **Rule ID**: `SV-222577r1043178_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-001184`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222578] APSC-DV-002240 - The application must destroy the session ID value and/or cookie on logoff or browser close.

- **Rule ID**: `SV-222578r1043179_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-001185`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222579] APSC-DV-002250 - Applications must use system-generated session identifiers that protect against session fixation.

- **Rule ID**: `SV-222579r1043180_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001664`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222580] APSC-DV-002260 - Applications must validate session identifiers.

- **Rule ID**: `SV-222580r1043180_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001664`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222581] APSC-DV-002270 - Applications must not use URL embedded session IDs.

- **Rule ID**: `SV-222581r1043180_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001664`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222582] APSC-DV-002280 - The application must not re-use or recycle session IDs.

- **Rule ID**: `SV-222582r1043180_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001664`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222583] APSC-DV-002290 - The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number generator.

- **Rule ID**: `SV-222583r1051270_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001188`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no browser interface, cookies, web storage, application-server session identifiers or session-ID lifecycle. A Kerberos credential cache is a reusable credential, not a browser session ID. The CES client does not create authenticated browser sessions.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp). Follow-up: Reassess if browser sessions or application session identifiers are introduced.

#### [V-222601] APSC-DV-002485 - The application must not store sensitive information in hidden fields.

- **Rule ID**: `SV-222601r1263598_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-002420`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT serves no HTML pages/forms, hidden fields, browser scripts or authenticated browser actions. The architecture has no XSS/CSRF or hidden-field surface. SOAP response parsing remains subject to the applicable XML and input-handling controls.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/launcher.cpp](../source/src/launcher.cpp); [source/README.md](../source/README.md)

#### [V-222602] APSC-DV-002490 - The application must protect from Cross-Site Scripting (XSS) vulnerabilities.

- **Rule ID**: `SV-222602r961158_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-001310`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT serves no HTML pages/forms, hidden fields, browser scripts or authenticated browser actions. The architecture has no XSS/CSRF or hidden-field surface. SOAP response parsing remains subject to the applicable XML and input-handling controls.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/launcher.cpp](../source/src/launcher.cpp); [source/README.md](../source/README.md)

#### [V-222603] APSC-DV-002500 - The application must protect from Cross-Site Request Forgery (CSRF) vulnerabilities.

- **Rule ID**: `SV-222603r961158_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001310`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT serves no HTML pages/forms, hidden fields, browser scripts or authenticated browser actions. The architecture has no XSS/CSRF or hidden-field surface. SOAP response parsing remains subject to the applicable XML and input-handling controls.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/launcher.cpp](../source/src/launcher.cpp); [source/README.md](../source/README.md)

#### [V-222607] APSC-DV-002540 - The application must not be vulnerable to SQL Injection.

- **Rule ID**: `SV-222607r961158_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-001310`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no relational database, SQL query interface, database security objects or production-to-test database exports. Active Directory access uses LDAP and is evaluated under directory/credential controls.
- **Comments / Evidence**: Evidence: [source/src/directory.hpp](../source/src/directory.hpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/README.md](../source/README.md)

#### [V-222615] APSC-DV-002760 - The application performing organization-defined security functions must verify correct operation of security functions.

- **Rule ID**: `SV-222615r961731_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002696`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is a credential acquisition/renewal utility, not an application designed to test correct operation of security functions on command or on a periodic security-verification schedule. Runtime validation of its own inputs/tickets and separate developer tests are not a deployed security-function testing service. These checks explicitly exempt products not designed/intended for such testing.
- **Comments / Evidence**: Evidence: [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Reassess if a deployed security-function verification capability is added; retain ordinary acceptance and annual failure testing.

#### [V-222616] APSC-DV-002770 - The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.

- **Rule ID**: `SV-222616r961734_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002699`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is a credential acquisition/renewal utility, not an application designed to test correct operation of security functions on command or on a periodic security-verification schedule. Runtime validation of its own inputs/tickets and separate developer tests are not a deployed security-function testing service. These checks explicitly exempt products not designed/intended for such testing.
- **Comments / Evidence**: Evidence: [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Reassess if a deployed security-function verification capability is added; retain ordinary acceptance and annual failure testing.

#### [V-222617] APSC-DV-002780 - The application must notify the ISSO and ISSM of failed security verification tests.

- **Rule ID**: `SV-222617r961185_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-001294`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is a credential acquisition/renewal utility, not an application designed to test correct operation of security functions on command or on a periodic security-verification schedule. Runtime validation of its own inputs/tickets and separate developer tests are not a deployed security-function testing service. These checks explicitly exempt products not designed/intended for such testing.
- **Comments / Evidence**: Evidence: [source/src/worker.cpp](../source/src/worker.cpp); [source/src/pkinit.hpp](../source/src/pkinit.hpp); [source/src/maintain.hpp](../source/src/maintain.hpp); [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Reassess if a deployed security-function verification capability is added; retain ordinary acceptance and annual failure testing.

#### [V-222618] APSC-DV-002870 - Unsigned Category 1A mobile code must not be used in the application in accordance with DoW policy.

- **Rule ID**: `SV-222618r1263599_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001166`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is a native Linux application and does not deliver applets, ActiveX, browser-executed code or other mobile code to remote users. Local administrator provisioning/export scripts are not a downloaded mobile-code application feature.
- **Comments / Evidence**: Evidence: [source/CMakeLists.txt](../source/CMakeLists.txt); [source/README.md](../source/README.md); [README.md](../README.md)

#### [V-222620] APSC-DV-002890 - Application web servers must be on a separate network segment from the application and database servers if it is a tiered application operating in the DoW DMZ.

- **Rule ID**: `SV-222620r1263602_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-002225`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not host a tiered web application with application web/database servers in a DMZ. Its outbound CES client does not make it the operator of the CES server tiers.
- **Comments / Evidence**: Evidence: [source/src/worker.cpp](../source/src/worker.cpp); [source/src/enroll.hpp](../source/src/enroll.hpp); [source/README.md](../source/README.md). Follow-up: Assess independently operated web/CA services and enclave placement under their applicable guidance.

#### [V-222625] APSC-DV-002950 - Execution flow diagrams and design documents must be created to show how deadlock and recursion issues in web services are being mitigated.

- **Rule ID**: `SV-222625r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000336`, `CCI-000366`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Enrollment Agent consumes the independently operated CES web service; CRAFT does not develop or host that service. The check explicitly exempts applications that consume web services without responsibility for their development. Local process/concurrency risks remain covered by other controls.
- **Comments / Evidence**: Evidence: [source/src/enroll.hpp](../source/src/enroll.hpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/README.md](../source/README.md)

#### [V-222645] APSC-DV-003140 - Application files must be cryptographically hashed prior to deploying to DoW operational networks.

- **Rule ID**: `SV-222645r1263618_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-000698`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: Not applicable by the system owner's determination: CRAFT is maintained and distributed as source in its GitHub repository and ships no binaries, packages, patches or signed release artifacts. There is no vendor package whose signature or published hash an installer could verify; each site builds from a chosen commit, which Git identifies by a cryptographic hash, and installs it under its own host software-management controls. Verification of the OS packages CRAFT depends on is inherited from the OS.
- **Comments / Evidence**: Evidence: System-owner determination, 11 October 2026 (source-only distribution; signed releases not applicable); [source/README.md](../source/README.md): Build; [source/CMakeLists.txt](../source/CMakeLists.txt). Follow-up: Reassess if binaries or packages are ever published.

#### [V-222662] APSC-DV-003280 - Default passwords must be changed.

- **Rule ID**: `SV-222662r1263622_rule`
- **Severity**: **HIGH** | **CCIs**: `CCI-003109`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not create, accept, prompt for, hash, change or distribute application user passwords/PINs or ship a default password. PKINIT uses private keys; directory/CES machine authentication uses an administrator-provisioned keytab or TLS key. Password lifecycle for externally managed host/AD accounts must be assessed in those systems.
- **Comments / Evidence**: Evidence: [source/src/pkinit.hpp](../source/src/pkinit.hpp): acquire_transport, refuse_prompt, get_tgt; [source/src/x509.hpp](../source/src/x509.hpp): read_key; [source/config/config.example](../source/config/config.example); [source/README.md](../source/README.md)

#### [V-222665] APSC-DV-003300 - The designer must ensure uncategorized or emerging mobile code is not used in applications.

- **Rule ID**: `SV-222665r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-001167`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT is a native Linux application and does not deliver applets, ActiveX, browser-executed code or other mobile code to remote users. Local administrator provisioning/export scripts are not a downloaded mobile-code application feature.
- **Comments / Evidence**: Evidence: [source/CMakeLists.txt](../source/CMakeLists.txt); [source/README.md](../source/README.md); [README.md](../README.md)

#### [V-222666] APSC-DV-003310 - Production database exports must have database administration credentials and sensitive data removed before releasing the export.

- **Rule ID**: `SV-222666r961863_rule`
- **Severity**: **MEDIUM** | **CCIs**: `CCI-002478`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT has no relational database, SQL query interface, database security objects or production-to-test database exports. Active Directory access uses LDAP and is evaluated under directory/credential controls.
- **Comments / Evidence**: Evidence: [source/src/directory.hpp](../source/src/directory.hpp); [source/src/worker.cpp](../source/src/worker.cpp); [source/README.md](../source/README.md)

#### [V-222672] APSC-DV-003360 - The application must generate audit records when concurrent logons from different workstations occur.

- **Rule ID**: `SV-222672r961833_rule`
- **Severity**: **LOW** | **CCIs**: `CCI-000172`
- **Evaluation Status**: **`Not_Applicable`**
- **Finding Details / Assessment**: CRAFT does not provide a server-side user logon service spanning remote workstations or maintain concurrent workstation sessions. Per-user local issuance locks are not a cross-workstation session monitor. The KDC and downstream services must assess their own concurrent logon auditing.
- **Comments / Evidence**: Evidence: [source/src/launcher.cpp](../source/src/launcher.cpp); [source/src/unprivileged.hpp](../source/src/unprivileged.hpp): rate_limit; [source/src/maintain.hpp](../source/src/maintain.hpp)

# Optional application access through GSS-Proxy and SELinux

Use this setup when an application should authenticate with CRAFT-issued user tickets without reading the source ticket cache. CRAFT acquires and maintains credentials as the issuer account; GSS-Proxy consumes that account's cache and serves an explicitly authorized application account over a Unix socket. The application uses a separate in-memory cache for opaque proxy credentials. CRAFT's broker keytab, operating modes and output format are unchanged.

This is an optional application deployment. The ordinary [direct-cache setup](../source/README.md#use) remains the default and needs neither GSS-Proxy nor this SELinux module. There is no new acquisition setting in `/etc/craft/config`.

## Choose a setup

| Setup | Instructions and boundary |
| --- | --- |
| Direct application access | [Standard CRAFT setup](../source/README.md) and [`with-craft`](../source/README.md#use); applications can read the user's cache |
| Isolated application account | [Host proxy setup](#host-proxy-setup) below; separate Unix identities deny direct cache access |
| SELinux enforcement | Add the [cache-label policy](#optional-selinux-policy) below and the application's own confinement policy |
| Contained applications in a user session | Upstream [GSS-Proxy userproxy setup](https://github.com/gssapi/gssproxy/blob/main/docs/Userproxy.md); expose the socket to the container and keep the issuer's home outside it |
| Kerberized NFS | Upstream [NFS client setup](https://github.com/gssapi/gssproxy/blob/main/docs/NFS.md#nfs-client); `rpc.gssd` has its own integration and cache-selection requirements |

GSS-Proxy interposes GSSAPI calls. Applications using raw Kerberos cache APIs, bundled Kerberos libraries or another mechanism implementation need separate validation. `klist` and `kvno` do not inspect the application's in-memory proxy cache from another process. Inspect the source cache from the trusted issuer account instead. See the upstream [application setup](https://github.com/gssapi/gssproxy/blob/main/docs/README.md).

Certificate modes supply a TGT, allowing GSS-Proxy to obtain service tickets under the user's existing permissions. Constrained Delegation supplies only the exact configured service tickets; an application must request a cached SPN and support service-only credentials. The proxy does not add a TGT or broaden that cache. Test the actual client, mechanism and SPN spelling. A TGT-backed proxy is not a service allowlist.

## Host proxy setup

The example separates `alice`, whose Linux name matches the AD account receiving tickets, from `craft-app`, the local application identity authorized to use them. It assumes a dedicated issuer home at `/var/lib/craft-users/alice`. For an existing account, use its actual NSS home and adapt the paths; do not move a user's home merely to follow the example. Do not add the application account to `craft` or `craft-users`.

### 1. Prepare the issuer and application

Complete [shared installation](../source/README.md#shared-linux-installation) and the selected [Enrollment Agent](../source/README.md#enrollment-agent-setup), [Key Trust](../source/README.md#key-trust-setup), [BYOC](../source/README.md#byoc-setup) or [Constrained Delegation](../source/README.md#constrained-delegation-setup) instructions. Keep `craft` and `craft-maintain` in the trusted issuer's execution context.

For new dedicated local accounts, provision the home and application account before completing that setup:

```sh
sudo install -d -o root -g root -m 0755 /var/lib/craft-users
sudo useradd --create-home --home-dir /var/lib/craft-users/alice --shell /bin/sh alice
sudo chmod 0700 /var/lib/craft-users/alice
sudo useradd --system --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin craft-app
```

Use the host's actual `nologin` path. The issuer home must remain issuer-owned and private. CRAFT keeps `.krb5cc_craft` issuer-owned, mode 0600. The application must not receive the source cache, issuer keytab, PEM files, issuer process descriptors or permission to run commands as the issuer.

### 2. Configure the proxy

Install the distribution's `gssproxy` package and MIT GSSAPI interposer on the application host. On RHEL-compatible systems use `sudo dnf install gssproxy`; on Ubuntu/Debian use `sudo apt-get install gssproxy`. Confirm the packaged `proxymech.so` entry in `/etc/gss/mech.d/`; use the package's actual library path instead of copying one from another distribution.

Review [80-craft-gssproxy.conf](../source/config/80-craft-gssproxy.conf), replacing its application account, socket and source-cache path. Its `euid` identifies the **consumer**; `cred_store = ccache:...` identifies the **issuer's cache**. This mapping explicitly authorizes that consumer to authenticate as the issuer. Use a separate application UID and socket for each credential scope. Multiple services with the same consumer UID are not isolated from one another by their socket names.

The example permits initiation only, disables impersonation/protocol transition and filters delegation. Both keytab stores point to `/dev/null`, so an expired or missing source cannot bootstrap credentials from a host keytab. Do not replace those entries with CRAFT's broker keytab, enable `allow_any_uid`, or enable `trusted` to resolve an authentication failure.

After editing the example, install it and the optional wrapper from the repository root:

```sh
sudo install -o root -g root -m 0600 source/config/80-craft-gssproxy.conf /etc/gssproxy/80-craft.conf
sudo install -o root -g root -m 0755 build/with-craft-gssproxy /usr/local/bin/with-craft-gssproxy
sudo systemctl enable --now gssproxy
sudo systemctl try-reload-or-restart gssproxy
```

The proxy daemon must be able to read the issuer's private home and credential cache; the usual system instance runs as root. Kerberos may also attempt to append service tickets to that cache. Some packaged policies deny those writes while allowing authentication; preserve private ownership and permissions, and inspect the actual failed operation before extending policy. See the [Rocky validation](../source/TESTING.md#rocky-gss-proxy-and-selinux-validation) for an observed example. Use administrator-controlled system Kerberos configuration with the correct realm/KDC, AES policy, DNS and time. Review other proxy stanzas so a broad default service cannot supply unintended credentials. The dedicated socket avoids sharing a default service selection with NFS or another application.

### 3. Acquire outside the application, then run through the socket

As the trusted issuer, run `craft` and inspect its returned cache using the [ordinary workflow](../source/README.md#use). For long-running services, start [`craft-maintain`](../source/README.md#long-running-jobs) against a long-lived controller PID belonging to the issuer. Supervise that controller separately from the consumer; the maintainer cannot watch a process owned by the different application UID. GSS-Proxy does not perform certificate acquisition, CRAFT renewal or service-batch refresh.

Configure the application's service command to run as `craft-app` through the wrapper, for example:

```sh
/usr/local/bin/with-craft-gssproxy /var/lib/gssproxy/craft-app.sock \
    /usr/bin/curl --fail --negotiate --user : https://portal.domain.local/
```

The wrapper sets `GSS_USE_PROXY=yes`, `GSSPROXY_SOCKET`, `GSSPROXY_BEHAVIOR=REMOTE_FIRST`, a fresh process-local `KRB5CCNAME=MEMORY:craft-gssproxy`, and unusable local keytab paths. It does not invoke CRAFT or expose its source-cache name. Do not use the ordinary `with-craft` wrapper for the isolated consumer. Never set the consumer's `KRB5CCNAME` to the source cache: the interposer stores opaque credentials in its selected cache and can replace its contents.

`REMOTE_FIRST` may attempt local GSSAPI after a proxy failure. The separate empty cache, unusable keytabs and filesystem/confinement boundary deny that path useful credentials. The upstream [interposer manual](https://github.com/gssapi/gssproxy/blob/main/man/gssproxy-mech.8.xml.in) documents `REMOTE_ONLY` as unsupported; do not treat an environment variable as the access-control boundary. This wrapper is for ordinary applications, not setuid/setgid or other `AT_SECURE` executions that may ignore its environment.

Applications must release and reacquire GSS credentials when CRAFT replaces the source. A new wrapper invocation starts with an empty proxy cache and observes current credentials. A long-lived process may retain an older encrypted credential handle or established service session; validate its refresh behavior and restart it when necessary. Cache replacement or deletion does not revoke issued tickets, proxy handles or established sessions.

## Optional SELinux policy

SELinux is configured on the host, independently of CRAFT's mode list. Keep it enforcing on hosts that use it. The supplied [craft_gssproxy.te](../source/selinux/craft_gssproxy.te) adds a private credential type and lets the packaged `gssproxy_t` domain access that type. It does not create a general application sandbox or confine the CRAFT launcher and workers. Separate Unix UIDs still deny the consumer direct access when its SELinux domain is unconfined.

For a dedicated issuer home under `/var/lib/craft-users`, build and install the module on the deployment's RHEL-compatible system:

```sh
sudo dnf install selinux-policy-devel policycoreutils-python-utils
mkdir -p build/selinux
cp source/selinux/craft_gssproxy.te build/selinux/
make -C build/selinux -f /usr/share/selinux/devel/Makefile craft_gssproxy.pp
sudo semodule -i build/selinux/craft_gssproxy.pp
sudo semanage fcontext -a -t craft_credential_t '/var/lib/craft-users/alice(/.*)?'
sudo restorecon -RFv /var/lib/craft-users/alice /var/lib/gssproxy
```

Adapt the rule to the actual dedicated home; use `semanage fcontext -m` if that exact local rule already exists. Label the **whole dedicated issuer home**, including the directory, rather than only `.krb5cc_craft`. CRAFT publishes by creating a randomly named temporary file and renaming it; a pathname rule alone is not applied during that rename. The private parent type gives temporary caches, locks and status files the private type from creation. Do not relabel a general interactive home with this example.

An existing confined application domain needs socket access, typically through the distribution policy interface `gssproxy_stream_connect(application_domain_t)` in its reviewed policy. It must have no read/manage access to `craft_credential_t`, no ability to transition to the issuer's context, and no ability to inspect the issuer's processes. An application running as the issuer's UID needs all of these SELinux restrictions to provide isolation; separate UIDs are the simpler default. Do not label the application `gssproxy_t` or grant it access to the source files.

The issuer's actual scheduler/launcher/maintainer domains must be allowed to manage this private home. The usual unconfined issuer context already can; a confined issuer needs an explicit policy extension covering its real workflow. Review transitions with CRAFT's privilege drop and `no_new_privs`, and verify the application's GSSAPI environment still takes effect. The upstream `selinux_context` proxy option is deprecated; use socket access rules and `euid` instead. See the [proxy configuration reference](https://github.com/gssapi/gssproxy/blob/main/man/gssproxy.conf.5.xml), [distribution policy interfaces](https://github.com/fedora-selinux/selinux-policy/blob/rawhide/policy/modules/contrib/gssproxy.if) and [Red Hat's custom-policy guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/writing-a-custom-selinux-policy_using-selinux).

## Deployment acceptance

Run these checks in the real application service context, not just an administrator's shell with the same Unix UID. Record `getenforce`, the process domains from `ps -eZ`, and labels from `ls -lZ` and `matchpathcon -V`.

1. Acquire as the issuer. Confirm the expected principal, AES tickets and mode-appropriate TGT/service-only contents with `klist`. Confirm issuer ownership and mode 0600.
2. From the consumer, prove that reading the source cache and issuer home fails, while the configured GSSAPI application authenticates as the intended issuer. Confirm proxy activity with `journalctl -u gssproxy` and the target server's authentication logs.
3. Repeat with a different local UID, absent source cache, absent interposer and unavailable dedicated proxy service. New authentication must fail without local/keytab fallback. Test a nonexistent socket without disrupting unrelated proxy users; stop a shared daemon only in a disposable test environment.
4. Exercise CRAFT acquisition, renewal and fresh authentication while the application is running. Check source ownership, labels on replacements and the application's credential refresh. Include Constrained Delegation batch refresh and rejection of an uncached SPN if using service-only tickets.
5. With SELinux enforcing, verify direct cache reads are denied in the application domain and all issuer/proxy operations succeed. Review `ausearch -m AVC,USER_AVC -ts recent` and explain denials before changing policy. Check labels after multiple replacements and a reboot; do not use permissive mode or blindly install `audit2allow` output as the acceptance result.

The [disposable container test](../source/TESTING.md#optional-gss-proxy-checks) covers the user-cache contract, actual GSSAPI exchanges and denial paths with a MIT KDC. Separate [Rocky validation](../source/TESTING.md#rocky-gss-proxy-and-selinux-validation) exercises actual CRAFT BYOC acquisition, automatic renewal, cache replacement and a confined application with SELinux enforcing. These fixtures do not establish AD acquisition through the proxy, a production application's credential refresh or confinement on another host. Repeat acceptance checks for the deployed application and policy.

## Return to direct access

Restore the application's ordinary direct-cache launch configuration only if granting that account cache access is intended. Remove its dedicated `/etc/gssproxy/80-craft.conf` stanza and reload GSS-Proxy; leave services used by other applications intact. If retiring the SELinux module, remove its local file-context rule, restore the dedicated home's distribution labels, then remove the module:

```sh
sudo semanage fcontext -d '/var/lib/craft-users/alice(/.*)?'
sudo restorecon -RFv /var/lib/craft-users/alice
sudo semodule -r craft_gssproxy
```

Preserve the issuer home's Unix permissions and verify any remaining application policy references before removing the module. Stop or restart consumers as needed; withdrawing proxy access does not invalidate tickets or sessions already issued.

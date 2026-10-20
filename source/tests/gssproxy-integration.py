#!/usr/bin/env python3
"""Exercise the optional application wrapper with a disposable MIT KDC and GSS-Proxy."""

import base64
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import sys
import time

import gssapi


def client(probe=False):
    signal.alarm(15)
    assert os.environ["KRB5CCNAME"] == "MEMORY:craft-gssproxy"
    assert os.environ["KRB5_CLIENT_KTNAME"] == "FILE:/dev/null"
    assert os.environ["KRB5_KTNAME"] == "FILE:/dev/null"
    mechanism = gssapi.OID.from_int_seq(sys.argv[2])
    name = gssapi.Name(sys.argv[3], name_type=gssapi.NameType.hostbased_service)
    context = gssapi.SecurityContext(
        name=name, mech=mechanism, usage="initiate",
        flags=[gssapi.RequirementFlag.mutual_authentication,
               gssapi.RequirementFlag.integrity, gssapi.RequirementFlag.confidentiality],
    )
    token = context.step()
    if probe:
        return
    print(base64.b64encode(token).decode(), flush=True)
    reply = base64.b64decode(input())
    assert context.step(reply) is None and context.complete
    wrapped = context.wrap(b"CRAFT proxy check", True).message
    print(json.dumps({"wrapped": base64.b64encode(wrapped).decode()}))


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def main():
    if os.getuid() != 0 or os.environ.get("CRAFT_DISPOSABLE_CONTAINER") != "yes":
        raise SystemExit("Run as root with CRAFT_DISPOSABLE_CONTAINER=yes, only in a disposable container.")
    wrapper = str(Path(sys.argv[1]).resolve() / "with-craft-gssproxy")
    root = Path("/run/craft-gssproxy-integration")
    root.mkdir(mode=0o755)
    (root / "services").mkdir()
    issuer, app, denied = "craft-proxy-issuer", "craft-proxy-app", "craft-proxy-denied"
    home = Path("/var/lib/craft-users") / issuer
    for user in (issuer, app, denied):
        run("useradd", "--no-create-home", "--home-dir",
            str(home) if user == issuer else "/nonexistent", user)
    account = pwd.getpwnam(issuer)
    home.mkdir(parents=True, mode=0o700)
    os.chown(home, account.pw_uid, account.pw_gid)
    source = home / ".krb5cc_craft"
    realm = "CRAFT.PROXY.TEST"
    proxy_socket = root / "app.sock"
    config = root / "krb5.conf"
    config.write_text(f"""[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false
 dns_lookup_realm = false
 dns_canonicalize_hostname = false
 qualify_shortname = ""
 rdns = false
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 {realm} = {{
  kdc = 127.0.0.1:10089
 }}
""")
    profile = root / "kdc.conf"
    profile.write_text(f"""[kdcdefaults]
 kdc_ports = 10089
 kdc_tcp_ports = 10089
[realms]
 {realm} = {{
  database_name = {root}/principal
  key_stash_file = {root}/stash
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
 }}
""")
    os.environ.update(KRB5_CONFIG=str(config), KRB5_KDC_PROFILE=str(profile), GSS_USE_PROXY="no")
    run("kdb5_util", "-r", realm, "create", "-s", "-P", "disposable-fixture")
    for principal, keytab in ((issuer, "issuer.keytab"), ("HTTP/localhost", "http.keytab")):
        run("kadmin.local", "-r", realm, "-q", f"addprinc -randkey {principal}")
        run("kadmin.local", "-r", realm, "-q", f"ktadd -k {root / keytab} {principal}")
    processes = []
    log = (root / "services.log").open("w")
    passed = 0

    def check(name, operation):
        nonlocal passed
        operation()
        passed += 1
        print(f"PASS {name}", flush=True)

    def issue():
        temporary = source.with_suffix(".new")
        run("kinit", "-k", "-t", str(root / "issuer.keytab"), "-c", f"FILE:{temporary}", f"{issuer}@{realm}")
        os.chown(temporary, account.pw_uid, account.pw_gid)
        temporary.chmod(0o600)
        temporary.replace(source)

    def command(user=app, mode="--client", mechanism="1.2.840.113554.1.2.2", endpoint=proxy_socket,
                target="HTTP@localhost"):
        return ["runuser", "-u", user, "--", wrapper, str(endpoint), "python3",
                str(Path(__file__).resolve()), mode, mechanism, target]

    def authenticate(mechanism="1.2.840.113554.1.2.2", environment=None):
        credentials = gssapi.Credentials(usage="accept", store={"keytab": str(root / "http.keytab")})
        context = gssapi.SecurityContext(creds=credentials, usage="accept")
        with subprocess.Popen(command(mechanism=mechanism), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, env=environment) as process:
            token = process.stdout.readline().strip()
            if not token:
                raise RuntimeError(process.communicate(timeout=10)[1])
            reply = context.step(base64.b64decode(token))
            result, error = process.communicate(base64.b64encode(reply).decode() + "\n", timeout=10)
            assert process.returncode == 0, error
            assert context.complete and str(context.initiator_name) == f"{issuer}@{realm}"
            clear = context.unwrap(base64.b64decode(json.loads(result)["wrapped"]))
            assert clear.encrypted and clear.message == b"CRAFT proxy check"
        assert source.stat().st_uid == account.pw_uid and source.stat().st_mode & 0o777 == 0o600

    def rejected(arguments, environment=None):
        result = subprocess.run(arguments, text=True, capture_output=True, timeout=15, env=environment)
        assert result.returncode != 0, "unexpected success"

    try:
        processes.append(subprocess.Popen(["krb5kdc", "-n", "-r", realm], stdout=log, stderr=log))
        for attempt in range(100):
            try:
                with socket.create_connection(("127.0.0.1", 10089), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        issue()
        example = Path(__file__).resolve().parent.parent / "config" / "80-craft-gssproxy.conf"
        service = example.read_text().replace("euid = craft-app", f"euid = {app}")
        service = service.replace("/var/lib/gssproxy/craft-app.sock", str(proxy_socket))
        service = service.replace("/var/lib/craft-users/alice/.krb5cc_craft", str(source))
        (root / "services" / "80-craft.conf").write_text(service)
        (root / "gssproxy.conf").write_text("[gssproxy]\n")
        proxy = subprocess.Popen(["gssproxy", "-i", "-c", str(root / "gssproxy.conf"),
                                  "-C", str(root / "services"), "-s", str(root / "default.sock")],
                                 stdout=log, stderr=log)
        processes.append(proxy)
        for attempt in range(100):
            if proxy_socket.is_socket():
                break
            time.sleep(0.05)
        check("application cannot read source cache",
              lambda: rejected(["runuser", "-u", app, "--", "cat", str(source)]))
        check("Kerberos authentication and encrypted message through proxy", authenticate)
        check("SPNEGO authentication and encrypted message through proxy", lambda: authenticate("1.3.6.1.5.5.2"))
        inherited = dict(os.environ, KRB5CCNAME=f"FILE:{source}", KRB5_KTNAME=str(root / "http.keytab"),
                         KRB5_CLIENT_KTNAME=str(root / "issuer.keytab"), GSSPROXY_BEHAVIOR="LOCAL_ONLY")
        check("inherited credential selections are replaced", lambda: authenticate(environment=inherited))
        check("unapproved UID cannot use the service", lambda: rejected(command(user=denied, mode="--probe")))
        issue()
        check("fresh application observes atomic source replacement", authenticate)
        temporary = source.with_suffix(".service")
        run("kvno", "-c", f"FILE:{source}", "--out-cache", f"FILE:{temporary}", f"HTTP/localhost@{realm}")
        os.chown(temporary, account.pw_uid, account.pw_gid)
        temporary.chmod(0o600)
        temporary.replace(source)
        assert "krbtgt/" not in run("klist", "-c", f"FILE:{source}").stdout
        check("service-only cache supports the exact Kerberos target", authenticate)
        check("service-only cache supports the exact SPNEGO target", lambda: authenticate("1.3.6.1.5.5.2"))
        check("service-only cache cannot acquire another target",
              lambda: rejected(command(mode="--probe", target="HTTP@uncached.localhost")))
        held = source.with_suffix(".held")
        source.replace(held)
        try:
            check("missing source fails without keytab acquisition", lambda: rejected(command(mode="--probe")))
        finally:
            held.replace(source)
        plugin = Path("/etc/gss/mech.d/proxymech.conf")
        disabled = plugin.with_suffix(".disabled")
        plugin.replace(disabled)
        try:
            check("missing interposer cannot use source or inherited keytabs",
                  lambda: rejected(command(mode="--probe"), environment=inherited))
        finally:
            disabled.replace(plugin)
        check("missing socket is rejected",
              lambda: rejected(command(endpoint=root / "absent.sock", mode="--probe")))
        proxy.terminate()
        proxy.wait(timeout=10)
        stale = root / "stale.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
            endpoint.bind(str(stale))
        check("unavailable daemon fails without local credentials",
              lambda: rejected(command(endpoint=stale, mode="--probe"), environment=inherited))
        print(f"{passed} passed. MIT fixtures; no AD acquisition or SELinux enforcement exercised.")
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    if sys.argv[1:2] in (["--client"], ["--probe"]):
        client(sys.argv[1] == "--probe")
    else:
        main()

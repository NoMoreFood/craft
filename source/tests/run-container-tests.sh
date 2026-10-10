#!/bin/sh
# Install synthetic fixtures and run the detached-maintainer integration harness.
#
# For a DISPOSABLE container only. This creates a test account, overwrites /etc/krb5.conf and replaces the
# installed launcher with a synthetic issuer. It assumes the default installation paths.
# Usage: CRAFT_DISPOSABLE_CONTAINER=yes tests/run-container-tests.sh BUILD_DIRECTORY
set -eu
build=${1:?usage: run-container-tests.sh BUILD_DIRECTORY}
if [ "$(id -u)" -ne 0 ] || [ "${CRAFT_DISPOSABLE_CONTAINER:-}" != yes ]; then
    echo "Run as root with CRAFT_DISPOSABLE_CONTAINER=yes, and only inside a disposable container." >&2
    exit 1
fi
id craft-maintain-test >/dev/null 2>&1 || useradd --create-home --shell /bin/sh craft-maintain-test
chmod 0700 /home/craft-maintain-test

# A KDC address that refuses connections: renewals must fail without touching the cache or the issuer.
printf '%s\n' '[libdefaults]' ' dns_lookup_kdc = false' ' udp_preference_limit = 1' \
    '[realms]' ' DOMAIN.LOCAL = {' '  kdc = 127.0.0.1:9' ' }' >/etc/krb5.conf

# Run the harness once per way of watching the job: a pidfd, and the /proc form used where pidfd_open is missing.
install -o root -g root -m 0755 "$build/craft-tests" /usr/local/bin/craft
for maintainer in craft-maintain craft-maintain-proc; do
    echo "== $maintainer"
    runuser -u craft-maintain-test -- "$build/craft-maintain-tests" "$build/$maintainer" "$build/craft-tests"
done

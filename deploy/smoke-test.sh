#!/usr/bin/env bash
# Start nova-cache.service on this machine as the deploy installs it, and
# check what the unit's sandbox could break: that the server starts, reads
# its signing key, accepts an authenticated write and refuses another, that
# a store another user owned becomes the service's, and that the server
# answers on loopback alone.
#
# The keys are made here and stand in for the host's.  The machine is a
# throwaway: the script installs into /usr/local/bin, /etc and /var/lib and
# removes nothing.
#
# Usage: smoke-test.sh SERVER
#   SERVER   the nova-cache-server binary to install
set -euo pipefail

server=${1:?the nova-cache-server binary}
here=$(cd "$(dirname "$0")" && pwd)

readonly PORT=5000
readonly STORE=/var/lib/nix-cache
readonly SIGNING_KEY_NAME=smoke-test-1
readonly WRITE_KEY=smoke-test-write-key
# A NAR's file name is its hash in base 32; the server stores any name of
# that shape.
readonly NAR=0000000000000000000000000000000000000000000000000000.nar
readonly BODY='smoke test'

base=http://127.0.0.1:$PORT

pass() { echo "ok    $*"; }
fail() {
  echo "FAIL  $*" >&2
  sudo journalctl -u nova-cache.service --no-pager -n 40 >&2 || true
  exit 1
}

# A store another user owns, as the host's is before this unit's first
# deploy there.
sudo mkdir -p "$STORE/nar"
echo kept | sudo tee "$STORE/nar/pre-existing" > /dev/null
sudo chown -R "$(id -un)" "$STORE"

# An Ed25519 key as Nix writes one: the name, then the seed and the public
# key in base 64.  Each is the last 32 bytes of its DER encoding.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
openssl genpkey -algorithm ed25519 -out "$work/key.pem"
{
  printf '%s:' "$SIGNING_KEY_NAME"
  {
    openssl pkey -in "$work/key.pem" -outform DER | tail -c 32
    openssl pkey -in "$work/key.pem" -pubout -outform DER | tail -c 32
  } | base64 -w 0
  echo
} > "$work/secret-key"
sudo install -D -m 0600 -o root -g root "$work/secret-key" /etc/nix-cache/secret-key
printf 'CACHE_API_KEY=%s\n' "$WRITE_KEY" |
  sudo sh -c 'umask 077; cat > /etc/nix-cache/env'

sudo install -m 0755 "$server" /usr/local/bin/nova-cache-server
sudo install -D -m 0644 "$here/nova-cache.sysusers" /etc/sysusers.d/nova-cache.conf
sudo systemd-sysusers /etc/sysusers.d/nova-cache.conf
sudo install -m 0644 "$here/nova-cache.service" /etc/systemd/system/nova-cache.service
sudo systemctl daemon-reload
sudo systemctl start nova-cache.service

curl --fail --silent --show-error --output /dev/null \
  --retry 10 --retry-connrefused --retry-delay 1 "$base/nix-cache-info" ||
  fail "the server does not answer on loopback"
[ "$(systemctl is-active nova-cache.service)" = active ] || fail "the service is not active"
pass "the server runs under the unit and answers on loopback"

# The landing page prints the public key of the signing key it loaded.
curl --fail --silent --show-error "$base/" | grep -q -F "$SIGNING_KEY_NAME:" ||
  fail "the landing page does not name the signing key, so the server did not read it"
pass "the server read its signing key"

code=$(printf '%s' "$BODY" | curl --silent --output /dev/null --write-out '%{http_code}' \
  -X PUT -H "Authorization: Bearer $WRITE_KEY" --data-binary @- "$base/nar/$NAR")
[ "$code" = 200 ] || fail "an authenticated write answered $code"
[ "$(curl --fail --silent --show-error "$base/nar/$NAR")" = "$BODY" ] ||
  fail "the written NAR does not read back"
pass "an authenticated write is stored and read back"

code=$(printf '%s' "$BODY" | curl --silent --output /dev/null --write-out '%{http_code}' \
  -X PUT -H "Authorization: Bearer wrong" --data-binary @- "$base/nar/1${NAR#0}")
[ "$code" = 401 ] || fail "a write with the wrong key answered $code"
pass "a write with the wrong key is refused"

for path in "$STORE" "$STORE/nar/pre-existing" "$STORE/nar/$NAR"; do
  owner=$(sudo stat -c %U "$path")
  [ "$owner" = nova-cache ] || fail "$path belongs to $owner"
done
pass "the store another user owned is the service's"

address=$(hostname -I | awk '{ print $1 }')
if curl --silent --max-time 3 --output /dev/null "http://$address:$PORT/nix-cache-info"; then
  fail "the server answers on $address"
fi
pass "the server does not answer on $address"

systemd-analyze security nova-cache.service --no-pager | tail -n 1

# nova-cache

[![CI](https://github.com/Novavero-AI/nova-cache/actions/workflows/ci.yml/badge.svg)](https://github.com/Novavero-AI/nova-cache/actions/workflows/ci.yml)
[![Hackage](https://img.shields.io/hackage/v/nova-cache.svg)](https://hackage.haskell.org/package/nova-cache)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

nova-cache implements the Nix binary cache protocol in Haskell: nix-base32,
NAR serialization (whole-tree and streaming), narinfo parsing, store paths,
Ed25519 signing and upload validation, and an optional WAI cache server.
Bounded xz, zstd and bzip2 codecs are the public `nova-cache:xz`,
`nova-cache:zstandard` and `nova-cache:bzip2` sublibraries, and the zstd codec
also compresses for uploads.

Parsing, formatting, hashing, signing and validation are pure. Reading and
writing trees, hashing files, the codecs, the store and the server run in
`IO`. nova-cache is the protocol layer under
[nova-nix](https://github.com/Novavero-AI/nova-nix).

## Installation

```cabal
build-depends: nova-cache >= 0.11 && < 0.12
```

The codecs are separate sublibraries, named alongside the main library:

```cabal
build-depends: nova-cache:{nova-cache, xz, zstandard} >= 0.11 && < 0.12
```

libbz2 and libzstd are bundled. liblzma comes from the `xz` package, which
prefers a system liblzma found through pkg-config and falls back to its bundled
sources. `constraints: xz -system-xz` in `cabal.project` forces the bundled
copy, as this repository does.

## Usage

```haskell
import NovaCache.Hash (hashBytes, formatNixHash)
import qualified Data.ByteString as BS

-- Hash file contents into sha256:<nix-base32>
hash <- formatNixHash . hashBytes <$> BS.readFile path
```

```haskell
import NovaCache.NarInfo (parseNarInfo)
import NovaCache.Signing (parseSecretKey, sign)

-- Parse a narinfo and sign it
case (parseNarInfo raw, parseSecretKey "mykey:base64...") of
  (Right ni, Right sk) -> print (sign sk ni)  -- Right "mykey:<base64 sig>"
  _                    -> error "parse failed"
```

```haskell
import NovaCache.Validate (validateFull)

-- Validate an upload: fields, NAR hash, file hash and signatures. Every
-- error is collected rather than stopping at the first.
case validateFull publicKey ni narBytes fileBytes of
  Right ()  -> accept
  Left errs -> reject errs
```

```haskell
import qualified Data.ByteString as BS
import NovaCache.NAR (defaultCaseHack, withNarSource)
import qualified NovaCache.Hash as Hash

-- Stream a tree's NAR and hash it in one pass, without holding the archive
-- in memory. NovaCache.NAR.Stream parses NARs incrementally, and the codec
-- sublibraries bound decompression by a narinfo's declared NarSize.
narHash <- withNarSource defaultCaseHack path $ \pull ->
  let go ctx = do
        chunk <- pull
        if BS.null chunk
          then pure (Hash.hashFinalize ctx)
          else go (Hash.hashUpdate ctx chunk)
   in go Hash.hashInit
```

## Server

```bash
cabal run --flag server nova-cache-server -- --port 5000 --store ./nix-cache
```

The protocol lives in the `NovaCache.Server` library module as a WAI
`Application`, so the cache can be embedded in another server with its own
root page. The bundled executable is one such embedding.

### Configuration

| Variable | Description |
| --- | --- |
| `PORT` | Listen port (default: 5000; also `--port`) |
| `HOST` | Bind host (default: all interfaces; also `--host`) |
| `NIX_CACHE_DIR` | Store directory (default: `./nix-cache`; also `--store`) |
| `CACHE_API_KEY` | Bearer token required for `PUT`. The server refuses to start without it unless `--allow-open-writes` is passed. |
| `SIGNING_KEY_FILE` | Ed25519 secret key file for server-side narinfo signing |
| `LOG_REQUESTS` | Set to `0` to disable request logging |

### Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Landing page: live stats and the cache public key |
| `GET` | `/nix-cache-info` | Cache metadata |
| `GET` | `/narinfo-hashes` | All cached narinfo hashes, newline-delimited (authenticated) |
| `GET` | `/<hash>.narinfo` | Fetch a narinfo |
| `GET` | `/nar/<file>` | Fetch a NAR (streamed from disk) |
| `PUT` | `/<hash>.narinfo` | Upload a narinfo (authenticated, validated; refused unless the NAR its `URL` names is stored with its `FileSize` and `FileHash`) |
| `PUT` | `/nar/<file>` | Upload a NAR (authenticated, streamed to disk) |

`HEAD` is answered wherever `GET` is.

### Reclaiming unreferenced NARs

A client uploads each NAR before its narinfo, so a NAR whose narinfo was
refused, or never sent because the push died, stays under `nar/` with nothing
referencing it. No endpoint deletes anything. The `reclaim-nars` subcommand
does, run on the host against the store directory:

```bash
nova-cache-server reclaim-nars --store /var/lib/nix-cache           # list
nova-cache-server reclaim-nars --store /var/lib/nix-cache --delete  # remove
```

- A NAR is eligible only once it is at least `--min-age-hours` old (default
  336, two weeks), measured from its modification time. A NAR is unreferenced
  until its push sends the narinfo, and a push can run for hours.
- If any narinfo cannot be read or parsed, or its `URL` is not `nar/<file>`,
  the run prints those narinfos, lists and deletes nothing, and exits nonzero:
  the NAR such a narinfo names is unknown, so no NAR can be called unreferenced.
- A deletion that fails is reported for that file, and the exit status is
  nonzero.
- The store root comes from `--store`, then `NIX_CACHE_DIR`, then
  `./nix-cache`, as for the server. A missing `narinfo/` or `nar/` directory is
  an error, never an empty store.

### Public cache

A public instance runs at `cache.novavero.ai`. It serves store paths that
nova-nix builds, which today means its Windows MinGW-w64 toolchain seed
([nova-nix#207](https://github.com/Novavero-AI/nova-nix/issues/207)). To use
it from Nix, add it to `/etc/nix/nix.conf`. On a multi-user install, Nix
ignores substituters set by users it does not trust.

```
extra-substituters = https://cache.novavero.ai
extra-trusted-public-keys = cache.novavero.ai-1:9gQ7tLWMM+2tdC9H5sKMJltDIPfD7X2GWlZe8Aa8hHQ=
```

## Building from source

Tested with GHC 9.14.1. CI uses the latest cabal-install release.

```bash
cabal update
cabal build all -f server --enable-tests --ghc-options="-Werror"
cabal test -f server --ghc-options="-Werror"
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

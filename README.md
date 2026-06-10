<div align="center">
<h1>nova-cache</h1>
<p><strong>The Nix binary cache protocol, in Haskell.</strong></p>
<p>nix-base32, NAR archives, narinfo, store paths, and Ed25519 signing — with an optional WAI cache server. A pure core; IO is confined to the compression, storage, and server boundaries.</p>

[![CI](https://github.com/Novavero-AI/nova-cache/actions/workflows/ci.yml/badge.svg)](https://github.com/Novavero-AI/nova-cache/actions/workflows/ci.yml)
[![Hackage](https://img.shields.io/hackage/v/nova-cache.svg)](https://hackage.haskell.org/package/nova-cache)
![GHC](https://img.shields.io/badge/GHC-9.8-purple)
![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)

</div>

---

## Installation

```cabal
build-depends: nova-cache
```

The `compression` flag (on by default) requires the system `liblzma`. Build
with `-f-compression` if you only need hashing, NAR, or narinfo.

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

-- Validate an upload: fields + NAR hash + file hash + signatures.
-- Pure, and every error is collected rather than failing on the first.
case validateFull publicKey ni narBytes fileBytes of
  Right ()  -> accept
  Left errs -> reject errs
```

## Server

```bash
cabal run --flag server nova-cache-server -- --port 5000 --store ./nix-cache
```

### Configuration

| Variable | Description |
| --- | --- |
| `PORT` | Listen port (default: 5000) |
| `NIX_CACHE_DIR` | Store directory (default: `./nix-cache`) |
| `CACHE_API_KEY` | Bearer token required for `PUT`. The server refuses to start without it unless `--allow-open-writes` is passed. |
| `SIGNING_KEY_FILE` | Ed25519 secret key file for server-side narinfo signing |
| `LOG_REQUESTS` | Set to `0` to disable request logging |

### Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/nix-cache-info` | Cache metadata |
| `GET` | `/narinfo-hashes` | All cached narinfo hashes, newline-delimited |
| `GET` | `/<hash>.narinfo` | Fetch a narinfo |
| `GET` | `/nar/<file>` | Fetch a NAR |
| `PUT` | `/<hash>.narinfo` | Upload a narinfo (authenticated, validated) |
| `PUT` | `/nar/<file>` | Upload a NAR (authenticated) |

### Public cache

A public instance runs at `cache.novavero.ai`:

```
extra-substituters = https://cache.novavero.ai
extra-trusted-public-keys = cache.novavero.ai-1:9gQ7tLWMM+2tdC9H5sKMJltDIPfD7X2GWlZe8Aa8hHQ=
```

## Build & test

```bash
cabal build
cabal test
```

Optional flags: `-f-compression` skips the `liblzma` dependency, and `--flag server` builds the cache server. Requires GHC 9.8+ and cabal-install 3.10+.

---

<p align="center"><sub>BSD-3-Clause · <a href="https://github.com/Novavero-AI">Novavero AI</a></sub></p>

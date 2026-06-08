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

## Modules

| Module | Purpose |
| --- | --- |
| `NovaCache.Base32` | Nix-specific base32 (`0123456789abcdfghijklmnpqrsvwxyz` alphabet) |
| `NovaCache.Base64` | Standard base64 encode/decode (re-exported) |
| `NovaCache.Hash` | SHA-256 hashing, formatted as `sha256:<nix-base32>` |
| `NovaCache.StorePath` | Store path parsing and rendering with validated hashes |
| `NovaCache.NAR` | NAR archive serialization and deserialization |
| `NovaCache.NarInfo` | `.narinfo` text format parsing and rendering |
| `NovaCache.Signing` | Ed25519 fingerprint signing and verification |
| `NovaCache.Validate` | Field, content-hash, and signature validation (all errors collected) |
| `NovaCache.Compression` | xz compression (behind the `compression` flag) |
| `NovaCache.Store` | Filesystem storage backend for narinfo and NAR files |

The full API is documented on [Hackage](https://hackage.haskell.org/package/nova-cache).

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
extra-trusted-public-keys = cache.novavero.ai-1:2yJK0UZWlDDTpThzEdqfGWaj+j3ljOCGoA50Ims47dM=
```

## CI cache seeding

A composite action pushes store paths to a nova-cache server from CI. It
resolves runtime paths via `nix-build`, diffs against the server's
`/narinfo-hashes`, and uploads only what is missing.

```yaml
- uses: Novavero-AI/nova-cache/.github/actions/seed@main
  with:
    cache-url: https://cache.example.com
    api-key: ${{ secrets.CACHE_API_KEY }}
```

Inputs: `cache-url` and `api-key` (required); `paths` and `parallel` (optional).

## Build

```bash
cabal build                          # library
cabal build -f-compression           # without liblzma
cabal test                           # tests
cabal build --ghc-options=-Werror    # warnings as errors
cabal build --flag server            # with the server
```

---

<p align="center"><sub>BSD-3-Clause · <a href="https://github.com/Novavero-AI">Novavero AI</a></sub></p>

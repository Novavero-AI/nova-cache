# Changelog

## 0.3.2.0 — 2026-03-18

### Server logging

- **Request logging** — Apache Combined format via `wai-extra` middleware,
  configurable with `LOG_REQUESTS=0` to disable.
- **Error logging** — auth rejections, validation failures, oversized uploads,
  and bad paths now logged to stderr with request method and path context.
- **`withLimitedBody` combinator** — extracted common body-limiting pattern from
  PUT handlers, reducing duplication.
- **`notFound` named constant** — replaces three inline 404 responses.
- Fixed `loadSigningKey` warnings going to stdout instead of stderr.

### Seed action fixes

- **Resolve runtime outputs, not derivations** — `nix-instantiate` replaced
  with `nix-build --no-out-link` so the cache stores actual binaries instead of
  `.drv` build recipes.
- **Filter uploads to diff-only** — `nix copy` exports transitive deps; uploads
  now filtered against the missing-hashes diff to avoid re-uploading cached paths.
- **Fix broken pipe** — `find | xargs` with `pipefail` caused spurious failures;
  now writes to intermediate files.
- **Fix xargs line-too-long** — large path lists passed via file instead of inline.
- **Diagnostic output** — upload failure HTTP codes now printed; `nix copy` errors
  no longer silenced.
- **Parallelism** — per-upload `--max-time` added (120s for NARs, 30s for narinfos).

### Server validation

- **Reject derivation narinfos** — `validateNarInfo` now rejects any narinfo
  where StorePath ends in `.drv` with a new `DerivationStorePath` error. Binary
  caches serve build outputs, not build recipes.
- 1 new test (75 total)

## 0.3.1.0 — 2026-03-07

### Drop `memory` dependency, use `ram`

- **`memory` → `ram`** — Replaced `memory` package with `ram` (modern, minimal replacement). Same `Data.ByteArray` API, drops the heavy `basement` transitive dependency. Fixes build failure with `crypton >= 1.1` which switched from `memory` to `ram` internally — `Data.ByteArray.ByteArrayAccess` instances were no longer compatible across packages.
- **`crypton >= 1.1` required** — Lower bound bumped from `1.0` to `1.1` so that `crypton` and `nova-cache` both link against `ram` for `ByteArrayAccess` instances. Older `crypton` versions used `memory`, causing instance mismatches at link time.
- All imports remain `Data.ByteArray` — no source-level changes needed for downstream consumers.

## 0.3.0.0 — 2026-02-28

### Breaking changes

- **`decompressXz`** signature changed from `ByteString -> ByteString` to
  `ByteString -> IO (Either String ByteString)` — catches lzma exceptions
  instead of crashing on malformed input
- **`writeNarInfo`** / **`writeNar`** now return `IO Bool` instead of `IO ()` —
  `False` indicates a rejected path (traversal, empty)

### Security

- **Request body size limit** — PUT endpoints reject bodies over 100 MB with
  413 Payload Too Large (prevents memory exhaustion)
- **Constant-time auth comparison** — API key check uses `constEq` from
  `Data.ByteArray` instead of `==` (prevents timing side-channel)

### Bug fixes

- **Safe UTF-8 decoding in NAR deserializer** — `decodeUtf8` replaced with
  `decodeUtf8'`; malformed UTF-8 in symlink targets or directory entry names
  now returns a parse error instead of throwing

### New features

- **`GET /narinfo-hashes`** endpoint — returns all cached narinfo hashes as
  newline-delimited text, enabling efficient cache diffing
- **`listNarInfoHashes`** function added to `NovaCache.Store`

### Improvements

- Server logs warnings to stderr when narinfo signing fails (parse error or
  sign error) instead of silently returning unsigned body
- Server returns 400 Bad Request when PUT paths fail sanitization instead of
  silently discarding the upload
- README: license badge and footer corrected from MIT to BSD-3-Clause
- README: `parallel` input documented in seed action table
- README: `CACHE_API_KEY` and `SIGNING_KEY_FILE` env vars documented
- Seed action: replaced per-path HEAD checks with single `GET /narinfo-hashes`
  call and local diff for dramatically faster cache seeding

## 0.2.4.1 — 2026-02-26

- License changed from MIT to BSD-3-Clause

## 0.2.4.0 — 2026-02-25

- New module: `NovaCache.Base64` — base64 encode/decode re-exported so
  downstream consumers don't need a direct `base64-bytestring` dependency
- No changes to existing modules

## 0.2.3.0 — 2026-02-23

- Drop `unix` dependency — `checkExecutable` now uses cross-platform
  `System.Directory.getPermissions` instead of `System.Posix.Files`
- Fixes Windows build (the `unix` package is not available on Windows)
- No API changes

## 0.2.2.0 — 2026-02-23

- Gate `NovaCache.Compression` and `lzma` dependency behind a `compression`
  cabal flag (default on, backwards compatible)
- Consumers that only need hashing/NAR/narinfo can build with `-compression`
  to avoid the system `liblzma` C dependency
- Compression tests moved to separate test suite (`nova-cache-compression-test`)
- No changes to any library source modules

## 0.2.1.0 — 2026-02-22

- Server: `validateNarInfo` wired into PUT handler — rejects malformed uploads
  with 400 Bad Request and collected validation errors
- Server: `Cache-Control: public, max-age=31536000, immutable` on narinfo and
  NAR GET responses for CDN edge caching
- Store: default priority changed from 30 to 50 (community cache fallback
  behind cache.nixos.org at 40)
- Seed action: fix round-trip validation to account for server-side signing;
  now verifies StorePath field, signature presence, and NAR fetchability
- Public binary cache documented with key and nix.conf instructions

## 0.2.0.0 — 2026-02-22

- New module: `NovaCache.Validate` — pure protocol validation layer
- `ValidationError` sum type with 10 constructors covering sizes, store paths,
  hash formats, content hashes, and Ed25519 signatures
- `validateNarInfo` — field semantic validation (non-negative sizes, parseable
  store paths/hashes/references), collects all errors instead of short-circuiting
- `validateNarHash` / `validateFileHash` — SHA-256 content hash verification
  against declared narinfo values
- `validateSignature` — Ed25519 signature verification against a trusted public
  key (at-least-one semantics, matching Nix behaviour)
- `validateFull` — composes all four stages, collecting errors across all
- 17 new tests (74 total across 9 groups)
- No new dependencies

## 0.1.0.0 — 2026-02-21

- Initial release (renamed from gb-nix-cache)
- Nix-base32 encoding/decoding
- SHA-256 hashing with Nix hash formatting
- Store path parsing and rendering
- NAR binary format serialization/deserialization
- NarInfo text format parsing/rendering
- Ed25519 signing and verification
- xz compression/decompression
- Filesystem storage backend
- Optional WAI cache server (behind `server` flag)
- Path traversal protection on all store operations
- Total port parsing (no partial `read`)
- 54 tests across 8 modules

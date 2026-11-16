# nova-cache

[![CI](https://github.com/Novavero-AI/nova-cache/actions/workflows/ci.yml/badge.svg)](https://github.com/Novavero-AI/nova-cache/actions/workflows/ci.yml)
[![Hackage](https://img.shields.io/hackage/v/nova-cache.svg)](https://hackage.haskell.org/package/nova-cache)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

nova-cache implements the Nix binary cache protocol in Haskell: nix-base32,
NAR serialization (whole-tree and streaming), narinfo parsing, store paths,
Ed25519 signing and upload validation, a WAI application for a cache server,
and an optional server executable.
Bounded xz, zstd and bzip2 codecs are the public `nova-cache:xz`,
`nova-cache:zstandard` and `nova-cache:bzip2` sublibraries, and the zstd codec
also compresses for uploads.

Parsing, formatting, hashing, signing, validation, one-shot xz decompression
and zstd compression are pure. Reading and writing trees, hashing files, the
streaming codecs, zstd and bzip2 decompression, the store and the server run
in `IO`. nova-cache is the protocol layer under
[nova-nix](https://github.com/Novavero-AI/nova-nix).

## Installation

```cabal
build-depends: nova-cache >= 0.13 && < 0.14
```

The codecs are separate sublibraries, named alongside the main library:

```cabal
build-depends: nova-cache:{nova-cache, xz, zstandard} >= 0.13 && < 0.14
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
  (Left err, _)        -> putStrLn err
  (_, Left err)        -> putStrLn err
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
CACHE_API_KEY=change-me cabal run --flag server nova-cache-server -- --port 5000 --store ./nix-cache
```

Without `CACHE_API_KEY` the server refuses to start. `--allow-open-writes` runs
it with unauthenticated writes and removals, for local testing only.

`GET /` answers a line of plain text. `--root-page FILE` serves `FILE` there
as HTML instead, such as a page about the cache; the server reads it once at
startup and refuses to start if it cannot.

The protocol lives in the `NovaCache.Server` library module as a WAI
`Application`, so the cache can be embedded in another server with its own
root page. The bundled executable is one such embedding. One server serves a
store directory: it orders its own removals against its own uploads.

### Configuration

| Variable | Description |
| --- | --- |
| `PORT` | Listen port (default: 5000; also `--port`) |
| `HOST` | Bind host (default: all interfaces; also `--host`) |
| `NIX_CACHE_DIR` | Store directory (default: `./nix-cache`; also `--store`) |
| `CACHE_API_KEY` | Bearer token for the requests marked authenticated below. The server refuses to start without it unless `--allow-open-writes` is passed. |
| `SIGNING_KEY_FILE` | Ed25519 secret key file for server-side narinfo signing |
| `LOG_REQUESTS` | Set to `0` to disable request logging |

### Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | A line of plain text, or the `--root-page` file |
| `GET` | `/nix-cache-info` | Cache metadata |
| `GET` | `/narinfo-hashes` | All cached narinfo hashes, newline-delimited (authenticated) |
| `GET` | `/<hash>.narinfo` | Fetch a narinfo |
| `GET` | `/nar/<file>` | Fetch a NAR (streamed from disk) |
| `PUT` | `/<hash>.narinfo` | Upload a narinfo (authenticated, validated; refused unless the NAR its `URL` names is stored with its `FileSize` and `FileHash`) |
| `PUT` | `/nar/<file>` | Upload a NAR (authenticated, streamed to disk) |
| `DELETE` | `/<hash>.narinfo` | Remove a narinfo; its NAR stays until a reclaim (authenticated) |
| `GET` | `/reclaim` | List what `POST /reclaim` would remove (authenticated) |
| `POST` | `/reclaim` | Remove the NARs no narinfo names and abandoned uploads (authenticated) |
| `POST` | `/nar/<file>/uploads` | Begin a multipart upload of a NAR (authenticated) |
| `PUT` | `/nar/<file>/uploads/<id>/<n>` | Upload part `n` of it (authenticated, streamed to disk) |
| `POST` | `/nar/<file>/uploads/<id>` | Complete it: join the parts into `nar/<file>` (authenticated) |

`HEAD` is answered wherever `GET` is.

### Uploading a NAR in parts

A proxy in front of the server can refuse a request body over its own limit,
as Cloudflare does over 100 MB on its Free and Pro plans. A NAR over such a
limit is uploaded in parts, one request each:

1. `POST /nar/<file>/uploads` answers `201` with the upload's id, followed by
   a newline, as the body, and `Location: uploads/<id>`.
2. `PUT /nar/<file>/uploads/<id>/<n>` sends part `n` as the body. Parts are
   numbered from 1 and go in order: part `n` is accepted once parts 1 to
   `n - 1` are held. A part sent again replaces the one held, so a part whose
   response was lost can be sent again.
3. `POST /nar/<file>/uploads/<id>` completes the upload. Its body declares
   how many parts were sent and how many bytes they hold together:

   ```
   Parts: 3
   FileSize: 107200936
   ```

   The server joins the parts into `nar/<file>` only if it holds that many
   parts and they join to that size. Nothing of an upload is under `nar/`
   before then. The narinfo follows as for a NAR sent in one request.

Each part is as large as the client chooses. The parts of an upload together
are held to the 4 GB of a single `PUT /nar/<file>`, and an upload to 10,000
parts.

| Status | Meaning |
| --- | --- |
| `400` | The file name, the part number or the completion body is not valid |
| `401` | The write key is missing or wrong |
| `404` | No such upload of that file: never begun, completed, or reclaimed |
| `409` | The part would leave a gap, or the server holds other parts or another size than the completion declares |
| `413` | The parts would hold more than 4 GB, the completion declares a `FileSize` over 4 GB, or its body is over 1 KB |

A part whose response is lost can be sent again. To a client that sends its
parts in order, a `404` or `409` for a part means the server no longer holds
the parts sent before it, such as an upload a reclaim removed, so it begins a new
upload. Completion joins the whole NAR before it answers, so its
response can be lost, or a retry can meet the first attempt still joining:
whenever the completion is answered with anything but `200`, or not at all, the
client uploads the narinfo, whose check of the NAR's `FileSize` and `FileHash`
decides whether it is stored, and begins a new upload if the narinfo is refused
for want of its NAR.

### Removing entries and reclaiming NARs

`DELETE /<hash>.narinfo` removes an entry. Its NAR stays under `nar/`, still
served, until a reclaim removes it. A narinfo uploaded for a path the cache
holds replaces the entry, as for a smaller encoding of the same NAR, and the
NAR the old narinfo named likewise stays until a reclaim.

A reclaim removes the NARs no narinfo names, and the multipart uploads nothing
has been written to, once each is old enough. `GET /reclaim` lists what
`POST /reclaim` removes. Both answer with a report in plain text.

```bash
auth="Authorization: Bearer $CACHE_API_KEY"
curl -fsS -X DELETE -H "$auth" https://cache.example/<hash>.narinfo  # remove an entry
curl -fsS -H "$auth" https://cache.example/reclaim                   # list
curl -fsS -X POST -H "$auth" https://cache.example/reclaim           # remove
```

- A NAR or an upload is eligible once it is at least `min-age-hours` old
  (default 336, two weeks), measured from its modification time, as in
  `POST /reclaim?min-age-hours=24`. A NAR is unreferenced until its push sends
  the narinfo, and a push can run for hours. Any other query is refused with
  `400`.
- If any narinfo cannot be read or parsed, or its `URL` is not `nar/<file>`,
  the reclaim answers `409` naming those narinfos and removes nothing: the NAR
  such a narinfo names is unknown, so no NAR can be called unreferenced.
- If the store holds NARs and no narinfo at all, the reclaim answers `409` and
  removes nothing: a store that lost its narinfos looks the same as one whose
  every NAR is unreferenced. Removing every entry leaves a store like that;
  stop the server to remove its NARs.
- A reclaim can run while pushes are in progress. A narinfo is never stored
  naming a NAR the reclaim removes, and a NAR uploaded during a reclaim is
  kept. A narinfo that arrives for a NAR the reclaim removed is refused, as
  when a client skipped uploading a NAR the cache held, which upstream's
  `nix copy` does; the client's next attempt uploads the NAR.
- Uploads wait while a reclaim or a `DELETE` runs, and a reclaim reads every
  narinfo, so on a store with many entries a reclaim holds pushes up for as
  long as that read takes.
- A Nix client holding a narinfo that names a removed NAR treats it as a
  missing substitute and tries its next substituter.
- A removal that fails is reported for that file, and the reclaim answers
  `500`.

### Public cache

A public instance runs at `cache.novavero.ai`. It serves the sources
nova-nix's Windows packages are built from and the closure of its Windows
`hello` recipe, which nova-nix's CI publishes on every push to its main
branch. To use it from Nix, add it to `/etc/nix/nix.conf`. On a multi-user
install, Nix ignores substituters set by users it does not trust.

```
extra-substituters = https://cache.novavero.ai
extra-trusted-public-keys = cache.novavero.ai-1:9gQ7tLWMM+2tdC9H5sKMJltDIPfD7X2GWlZe8Aa8hHQ=
```

## Building from source

Tested with GHC 9.14.1. CI uses the latest cabal-install release.

```bash
cabal update
cabal build all -f server --enable-tests --ghc-options="-Werror"
cabal test -f server --enable-tests --ghc-options="-Werror"
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

-- | The cache.novavero.ai landing page.
--
-- Deployment branding lives here, in the executable: the
-- "NovaCache.Server" library is brand-free, taking whatever root
-- response its embedder supplies, so other operators running their own
-- cache never ship this page.
module LandingPage (landingResponse) where

import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Network.HTTP.Types as HTTP
import Network.Wai (Response, responseLBS)
import NovaCache.Store (CacheInfo (..), FileStore, getCacheInfo)

-- | Build the @GET \/@ response: the branded page around live values
-- (store-path count, store dir, signing status, public key).
--
-- The count comes from the injected action, not a store scan here: this
-- route is unauthenticated, so its per-request work must stay bounded -
-- the caller supplies a TTL-cached counter ('NovaCache.Server.newTTLCache').
landingResponse :: IO Int -> FileStore -> Bool -> Maybe Text -> IO Response
landingResponse countPaths store signingEnabled pubKey = do
  pathCount <- countPaths
  let body = TE.encodeUtf8 (landingHtml (getCacheInfo store) signingEnabled pubKey pathCount)
  pure (responseLBS HTTP.status200 htmlHeaders (BL.fromStrict body))

-- | The landing page markup.  Static apart from four live values; styled
-- to match novavero.ai.  Nothing user-supplied is interpolated - the key
-- line is operator configuration - so no escaping is needed.
landingHtml :: CacheInfo -> Bool -> Maybe Text -> Int -> Text
landingHtml info signingEnabled pubKey pathCount =
  T.unlines
    [ "<!DOCTYPE html>",
      "<html lang=\"en\">",
      "<head>",
      "<meta charset=\"UTF-8\" />",
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />",
      "<title>cache.novavero.ai - Nix binary cache</title>",
      "<meta name=\"description\" content=\"The Novavero Nix binary cache, serving store paths for nova-nix - the Windows-native Nix.\" />",
      "<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml," <> novaveroLogoSvgEscaped <> "\" />",
      "<style>",
      "* { margin: 0; padding: 0; box-sizing: border-box; }",
      "body { background: #0a0b0e; color: #d6d9de; -webkit-font-smoothing: antialiased; font-family: 'Inter', system-ui, sans-serif; line-height: 1.75; }",
      "body::before { content: ''; position: fixed; inset: 0 0 auto 0; height: 320px; pointer-events: none; background: radial-gradient(ellipse 70% 100% at 50% -20%, rgba(52,211,153,0.07), transparent 70%); }",
      ".container { max-width: 720px; margin: 0 auto; padding: 80px 24px; position: relative; }",
      "a { color: #34d399; text-decoration: none; }",
      "a:hover { text-decoration: underline; }",
      ".brand { display: flex; align-items: center; gap: 14px; margin-bottom: 0.75rem; }",
      ".brand svg { width: 44px; height: 44px; border-radius: 10px; }",
      "h1 { color: #fff; font-size: 1.6rem; font-family: ui-monospace, Consolas, monospace; }",
      ".tagline { color: #9ca3af; margin-bottom: 2.5rem; }",
      ".stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 2.5rem; }",
      ".stat { padding: 16px; border: 1px solid #232733; border-radius: 12px; text-align: center; }",
      ".stat .value { color: #fff; font-size: 1.4rem; font-weight: 600; }",
      ".stat .label { color: #6b7280; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }",
      "h2 { color: #fff; font-size: 1rem; margin: 2rem 0 0.5rem; }",
      "p { font-size: 0.9rem; margin-bottom: 0.75rem; }",
      "pre { background: #0d0f14; border: 1px solid #232733; border-radius: 8px; padding: 14px; white-space: pre-wrap; word-break: break-all; margin: 0.75rem 0; }",
      "code { font-family: ui-monospace, Consolas, monospace; font-size: 0.85rem; color: #e5e7eb; }",
      ".footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #232733; font-size: 0.85rem; color: #6b7280; }",
      "</style>",
      "</head>",
      "<body>",
      "<div class=\"container\">",
      "<div class=\"brand\">" <> novaveroLogoSvg <> "<h1>cache.novavero.ai</h1></div>",
      "<p class=\"tagline\">Nix binary cache - serving store paths for <a href=\"https://github.com/Novavero-AI/nova-nix\">nova-nix</a>, the Windows-native Nix.</p>",
      "<div class=\"stats\">",
      "<div class=\"stat\"><div class=\"value\">" <> T.pack (show pathCount) <> "</div><div class=\"label\">store paths</div></div>",
      "<div class=\"stat\"><div class=\"value\">" <> (if signingEnabled then "ed25519" else "off") <> "</div><div class=\"label\">signing</div></div>",
      "<div class=\"stat\"><div class=\"value\">" <> T.pack (show (ciPriority info)) <> "</div><div class=\"label\">priority</div></div>",
      "</div>",
      "<h2>Use it</h2>",
      "<pre><code>substituters = https://cache.novavero.ai" <> trustAnchorLine <> "</code></pre>",
      "<p>Store dir: <code>" <> ciStoreDir info <> "</code> &middot; protocol endpoints: <code>/nix-cache-info</code>, <code>/&lt;hash&gt;.narinfo</code>, <code>/nar/&lt;file&gt;</code></p>",
      "<h2>What this is</h2>",
      "<p>The binary cache behind the Novavero Nix toolchain. Powered by <a href=\"https://github.com/Novavero-AI/nova-cache\">nova-cache</a>, a Haskell implementation of the Nix binary cache protocol. Read about the first package built by Nix natively on Windows on <a href=\"https://novavero.ai/blog/first-native-windows-nix-build.html\">the blog</a>.</p>",
      "<div class=\"footer\"><a href=\"https://novavero.ai\">Novavero AI</a> &middot; Waterloo, Canada</div>",
      "</div>",
      "</body>",
      "</html>"
    ]
  where
    trustAnchorLine = maybe "" ("\ntrusted-public-keys = " <>) pubKey

-- | The Novavero mark (the novavero.ai favicon), inlined so the page stays
-- a single self-contained response with no external assets.
novaveroLogoSvg :: Text
novaveroLogoSvg =
  "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\" role=\"img\" aria-label=\"Novavero\">"
    <> "<g fill=\"#0a0f1a\"><rect width=\"64\" height=\"64\" rx=\"14\" ry=\"14\"/></g>"
    <> "<g fill=\"#ffffff\"><path d=\"M12 54L19 54L23 10L16 10Z\"/><path d=\"M16 10L23 10L48 54L41 54Z\"/><path d=\"M41 54L48 54L52 10L45 10Z\"/></g>"
    <> "</svg>"

-- | The same mark, URL-escaped for a data-URI favicon link.
novaveroLogoSvgEscaped :: Text
novaveroLogoSvgEscaped =
  T.concatMap escapeForDataUri novaveroLogoSvg
  where
    escapeForDataUri c = case c of
      '<' -> "%3C"
      '>' -> "%3E"
      '"' -> "%22"
      '#' -> "%23"
      other -> T.singleton other

-- | Content-Type and caching headers for the landing page.  Stats change as
-- paths are added, so it stays briefly cacheable but revalidates.
htmlHeaders :: HTTP.ResponseHeaders
htmlHeaders =
  [ (HTTP.hContentType, "text/html; charset=utf-8"),
    (HTTP.hCacheControl, "public, max-age=300, must-revalidate")
  ]

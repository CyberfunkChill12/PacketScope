# Third-party notices

## Public Suffix List
- Bundled at `PacketScope/Resources/public_suffix_list.dat`, used only to
  decide whether a domain is itself a public suffix (such entries are never
  treated as indicators, and are never sent anywhere).
- Version: 2026-10-22 (from the list header; also shown at runtime via
  `PublicSuffix.versionDate`).
- Source: https://publicsuffix.org/list/
- License: Mozilla Public License 2.0 (MPL 2.0). © the Public Suffix List
  contributors.

## Threat feeds
Feed names, licenses, and attribution text are recorded per feed in the
app's feed registry (`FeedRegistry` in ThreatFeeds.swift) and are shown in
Settings and in exported reports. abuse.ch feeds are CC0; Spamhaus DROP is
used under the Spamhaus DROP terms with its attribution kept. ThreatFox and
URLhaus require the user's own abuse.ch Auth-Key and are off by default.

## TLS fingerprints
JA4 (client) is computed locally for display and matching. The JA4 method
is BSD-licensed (FoxIO). No other JA4+ methods (JA4S/JA4H/JA4X, which
require an OEM license) are implemented.

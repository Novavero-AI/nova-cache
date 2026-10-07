# Contributing to nova-cache

nova-cache is a project of Novavero AI Inc. Thanks for your interest - issues
and pull requests are welcome.

## Ground rules

- Keep PRs focused; one change per PR.
- Code must build warning-clean and pass the test suite (`cabal build && cabal test`).
- Match the existing style (ormolu-formatted, hlint-clean).

## Changelog

User-visible changes get a bullet in a new file under `changelog.d/`, named
after the change (`changelog.d/narinfo-unknown-fields.md`): a bold lead
sentence, then the why (the upstream behavior matched, the hazard closed, the
reason the obvious approach does not work) in full sentences. Match the
entries already in `CHANGELOG.md`.

One file per entry rather than one shared section, because every branch
appending to the same section collides there and nowhere else.

At release the fragments are assembled under the new version heading with
`scripts/assemble-changelog.sh` and removed. The publish workflow refuses to
upload unless the top section of `CHANGELOG.md` is that version, dated.

## Licensing of contributions

nova-cache is licensed under Apache-2.0. Per Section 5 of the license, any
contribution intentionally submitted for inclusion in this project is licensed
under Apache-2.0, without additional terms or conditions. You keep the
copyright to your work. Submit only work you have the right to license.

This is the standard inbound=outbound arrangement: you contribute under the
same terms you received the project under, nothing more.

# kinetra-license

The license token library used by Kinetra. It defines the signed token format, the
trusted key set and its rotation, the revocation list, beta status, the entitlement
catalog and the offline license policy.

It is pure Rust with no I/O, no clock and no randomness; callers pass those in, so the
server and the app reach the same result for the same inputs.

## How Kinetra uses it

- The Kinetra server builds it with the `sign` feature to issue license tokens, key-set
  updates and revocation lists.
- The Kinetra desktop app builds it without `sign`. It only verifies tokens against the
  public keys compiled into it and evaluates them offline with `evaluate()`.
- Both run the committed test vectors in `tests/vectors/tokens.json`, so they agree on
  the format.

```toml
kinetra-license = { git = "https://github.com/KinetraLive/kinetra-license", tag = "license-vX.Y.Z" }
```

## Security

Tokens are Ed25519 signatures. Their security rests on the server's private signing key,
which is never in this repository. Everything here is public by design: the format, the
policy and the verification code. The keys in `tests/` are derived from fixed, public
seeds and are for tests only.

## Develop

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-features
# Only when the format changes on purpose:
cargo test --all-features --test vectors -- --ignored regenerate
```

Releases are tags `license-vX.Y.Z`. A change to the token format or claims needs a new
format version (`kntr2`), not an edit of `kntr1`.

Commit messages must not carry AI-tool attribution lines. Enable the hook that strips
them:

```sh
git config core.hooksPath hooks
```

## License

Copyright (C) 2026 Rørvik Medieteknikk

Licensed under the GNU Affero General Public License v3.0 only (`AGPL-3.0-only`). See
[LICENSE](LICENSE).

# redact-crypto
[![License: GPL-3.0](https://badgen.net/github/license/pauwels-labs/redact-crypto?color=blue)](https://opensource.org/licenses/GPL-3.0) [![crates.io](https://badgen.net/crates/v/redact-crypto?color=blue)](https://crates.io/crates/redact-crypto) [![docs.rs](https://img.shields.io/docsrs/redact-crypto?style=flat)](https://docs.rs/redact-crypto) [![Coverage Status](https://badgen.net/coveralls/c/github/pauwels-labs/redact-crypto/main)](https://coveralls.io/github/pauwels-labs/redact-crypto?branch=main)

redact-crypto is the backing library for Redact's encrypted type system. It allows consuming crates to fluidly request and store data that can be either plaintext data, encrypted data, or a reference to another location where the data is. It also allows code to then resolve any received data into its final plaintext.

Also contains implementations of the storage traits. Current supported implementations are:
- mongodb
- redact-store

## Docs & Support
Docs are available at [docs.redact.ws](https://docs.redact.ws).

Join us in our Keybase channel! You can download the keybase client [here](https://keybase.io/download).

Once there, click on Teams, select Join a team, and our team name is pauwelslabs.

Once you're in, Redact discussion happens in the #redact channel.

Discussions in the Keybase team should be respectful, focused on Redact, and free of profanity.

# subgrind

Fast **vanity address generator** for Substrate / Polkadot / Bittensor.
It grinds random BIP39 mnemonics (12 or 24 words) and derives the SS58 account
address until one matches a regex.

Addresses match `subkey` / Polkadot.js exactly — verified against the Substrate
dev-phrase test vector (`cargo test`).

## Install

```bash
cargo install subgrind
```

Or build from source:

```bash
cargo build --release
```

For maximum throughput on the machine you'll run it on, enable the host CPU's
full instruction set:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

> Don't use `target-cpu=native` for binaries you redistribute — they may crash
> with `SIGILL` on a different/older CPU.

## Usage

```bash
subgrind <PATTERN> [--prefix 42] [--scheme sr25519|ed25519|ecdsa] [--words 12|24] [--threads N]
subgrind --verify "<mnemonic>" [--scheme ...] [--prefix ...]
```

- `<PATTERN>` — a **regex** matched against the whole address string.
- `--prefix` — SS58 network prefix (default `42` generic Substrate and Bittensor; `0` Polkadot, `2` Kusama).
- `--scheme` — `sr25519` (default), `ed25519`, or `ecdsa`.
- `--words` — mnemonic length, `12` (default) or `24`.
- `--threads` — worker count (default: all logical cores).
- `--verify` — re-derive and print the address for an existing mnemonic (cross-check a result).

### Examples

```bash
subgrind 'SEEK$'          # address ends with SEEK
subgrind '(?i)dot$'       # ends with "dot", case-insensitive
subgrind '[a-z]SEEK$'     # ends with SEEK, preceded by a lowercase letter
subgrind 'KSM$' --prefix 2 --scheme ed25519 --words 24
```

The program prints progress (attempts/s) to **stderr** and, on the first match,
the result to **stdout**, then exits.

## Notes

- **Pattern feasibility.** The leading character is fixed by the prefix (prefix 42
  → addresses start with `5`, Polkadot prefix 0 → `1`), so `^...` anchors beyond
  that first char are heavily constrained. Suffix (`$`) and contains-patterns are
  the natural fit. Difficulty grows ~×58 per extra fixed base58 character.
- **ecdsa** matches the 32-byte *account* address (`SS58(blake2_256(pubkey))`) —
  the address wallets and explorers display.
- **Security.** Keys are generated from a per-thread ChaCha20 CSPRNG seeded from
  the OS. The found mnemonic is a real secret — store it securely and avoid
  redirecting it into files that might get committed or synced.
- **Speed.** The bottleneck is PBKDF2-HMAC-SHA512 (2048 rounds), as mandated by
  Substrate's key derivation.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

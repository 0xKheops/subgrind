//! Exact Substrate key derivation for a BIP39 mnemonic with an EMPTY derivation
//! path and no password. Mirrors `substrate-bip39` + `sp-core` so the addresses
//! produced here match `subkey` and Polkadot.js.
//!
//! Pipeline: entropy -> PBKDF2-HMAC-SHA512 seed -> keypair -> account -> SS58.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use clap::ValueEnum;
use ring::pbkdf2;
use schnorrkel::{ExpansionMode, MiniSecretKey};
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly};
use std::num::NonZeroU32;

/// blake2_256 — 32-byte Blake2b, used for ECDSA account ids.
type Blake2b256 = Blake2b<U32>;

const PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(2048).unwrap();

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Scheme {
    Sr25519,
    Ed25519,
    Ecdsa,
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scheme::Sr25519 => "sr25519",
            Scheme::Ed25519 => "ed25519",
            Scheme::Ecdsa => "ecdsa",
        })
    }
}

/// `substrate-bip39::seed_from_entropy`: PBKDF2-HMAC-SHA512 over the raw entropy
/// (IKM), salt = b"mnemonic", 2048 iterations, 64-byte output. The first 32
/// bytes are the seed handed to keypair construction.
#[inline]
fn seed_from_entropy(entropy: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 64];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        PBKDF2_ITERATIONS,
        b"mnemonic",
        entropy,
        &mut out,
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    seed
}

/// Derive the 32-byte account id for the given scheme. Returns `None` only when
/// the seed is an invalid secp256k1 scalar (probability ~2^-128, ECDSA only).
#[inline]
pub fn derive_account(
    entropy: &[u8],
    scheme: Scheme,
    secp: &Secp256k1<SignOnly>,
) -> Option<[u8; 32]> {
    let seed = seed_from_entropy(entropy);
    match scheme {
        Scheme::Sr25519 => {
            // sp-core: MiniSecretKey::from_bytes(seed).expand_to_keypair(Ed25519)
            let mini = MiniSecretKey::from_bytes(&seed).ok()?;
            let kp = mini.expand_to_keypair(ExpansionMode::Ed25519);
            Some(kp.public.to_bytes())
        }
        Scheme::Ed25519 => {
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            Some(sk.verifying_key().to_bytes())
        }
        Scheme::Ecdsa => {
            // Account id = blake2_256(compressed 33-byte public key).
            let sk = SecretKey::from_slice(&seed).ok()?;
            let pk = PublicKey::from_secret_key(secp, &sk);
            let compressed = pk.serialize(); // [u8; 33]
            let mut h = Blake2b256::new();
            h.update(compressed);
            let digest = h.finalize();
            let mut account = [0u8; 32];
            account.copy_from_slice(&digest);
            Some(account)
        }
    }
}

/// Encode a 32-byte account id as an SS58 address for the given network prefix.
pub fn ss58_encode(account: &[u8], prefix: u16) -> String {
    let ident = prefix & 0b0011_1111_1111_1111; // 14-bit network identifier
    let mut body: Vec<u8> = match ident {
        0..=63 => vec![ident as u8],
        _ => {
            let first = ((ident & 0b0000_0000_1111_1100) >> 2) as u8;
            let second = ((ident >> 8) as u8) | (((ident & 0b0000_0000_0000_0011) as u8) << 6);
            vec![first | 0b0100_0000, second]
        }
    };
    body.extend_from_slice(account);

    // checksum = blake2b_512("SS58PRE" || prefix_bytes || account)[0..2]
    let mut h = Blake2b512::new();
    h.update(b"SS58PRE");
    h.update(&body);
    let checksum = h.finalize();
    body.extend_from_slice(&checksum[..2]);

    bs58::encode(body).into_string()
}

/// Full pipeline: entropy -> SS58 address string for the given scheme/prefix.
#[inline]
pub fn derive_address(
    entropy: &[u8],
    scheme: Scheme,
    prefix: u16,
    secp: &Secp256k1<SignOnly>,
) -> Option<String> {
    let account = derive_account(entropy, scheme, secp)?;
    Some(ss58_encode(&account, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    // Substrate dev phrase, root key (empty derivation path).
    const DEV: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sr25519_matches_dev_vector() {
        let m = Mnemonic::parse(DEV).unwrap();
        let entropy = m.to_entropy();
        let secp = Secp256k1::signing_only();

        let account = derive_account(&entropy, Scheme::Sr25519, &secp).unwrap();
        assert_eq!(
            hex(&account),
            "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"
        );

        let addr = ss58_encode(&account, 42);
        assert_eq!(addr, "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV");
    }

    #[test]
    fn ss58_prefix_changes_address_text() {
        // Same account, different network prefix => different leading chars.
        let account = [0u8; 32];
        let polkadot = ss58_encode(&account, 0);
        let substrate = ss58_encode(&account, 42);
        assert_ne!(polkadot, substrate);
    }

    #[test]
    fn schemes_are_deterministic_and_distinct() {
        let entropy = [7u8; 32];
        let secp = Secp256k1::signing_only();
        let sr = derive_address(&entropy, Scheme::Sr25519, 42, &secp).unwrap();
        let ed = derive_address(&entropy, Scheme::Ed25519, 42, &secp).unwrap();
        let ec = derive_address(&entropy, Scheme::Ecdsa, 42, &secp).unwrap();

        // Same input always yields the same address.
        assert_eq!(
            sr,
            derive_address(&entropy, Scheme::Sr25519, 42, &secp).unwrap()
        );
        // Each scheme yields a distinct address.
        assert_ne!(sr, ed);
        assert_ne!(sr, ec);
        assert_ne!(ed, ec);
        // Prefix-42 (32-byte account) addresses all start with '5'.
        for addr in [&sr, &ed, &ec] {
            assert!(addr.starts_with('5'), "{addr} should start with '5'");
        }
    }
}

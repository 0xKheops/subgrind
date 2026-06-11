//! subgrind — grind random BIP39 mnemonics until the derived SS58 address
//! (empty derivation path) matches a regex. Multi-threaded.

mod derive;

use bip39::Mnemonic;
use clap::Parser;
use derive::{derive_address, Scheme};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use secp256k1::Secp256k1;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "subgrind",
    about = "Brute-force Substrate/Polkadot vanity addresses (BIP39 mnemonic, empty derivation path).",
    long_about = "Generates random BIP39 mnemonics and derives the SS58 account address \
                  with an empty derivation path until one matches the given regex.\n\n\
                  The regex matches the whole address string. Examples:\n  \
                  'SEEK$'   address ends with SEEK\n  \
                  '(?i)dot' contains 'dot', case-insensitive\n\n\
                  Note: a prefix-42 address always starts with '5', so '^...' patterns are \
                  constrained by that fixed leading character."
)]
struct Cli {
    /// Regex the SS58 address must match, e.g. 'SEEK$'.
    #[arg(required_unless_present = "verify")]
    pattern: Option<String>,

    /// SS58 network prefix (42 = generic Substrate, 0 = Polkadot, 2 = Kusama).
    #[arg(long, default_value_t = 42)]
    prefix: u16,

    /// Signature scheme.
    #[arg(long, value_enum, default_value_t = Scheme::Sr25519)]
    scheme: Scheme,

    /// Mnemonic length: 12 or 24 words.
    #[arg(long, default_value_t = 12, value_parser = parse_words)]
    words: u8,

    /// Worker threads (default: all logical cores).
    #[arg(long)]
    threads: Option<usize>,

    /// Derive + print the address for an existing mnemonic, then exit (cross-check a result).
    #[arg(long, value_name = "MNEMONIC")]
    verify: Option<String>,
}

fn parse_words(s: &str) -> Result<u8, String> {
    match s {
        "12" => Ok(12),
        "24" => Ok(24),
        _ => Err("must be 12 or 24".to_string()),
    }
}

fn main() {
    let cli = Cli::parse();

    if let Some(phrase) = cli.verify.as_deref() {
        run_verify(phrase, cli.scheme, cli.prefix);
        return;
    }

    let pattern = cli.pattern.expect("pattern is required unless --verify");
    let re = Arc::new(Regex::new(&pattern).unwrap_or_else(|e| {
        eprintln!("invalid regex: {e}");
        std::process::exit(2);
    }));

    let nthreads = cli.threads.filter(|&n| n > 0).unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });

    let scheme = cli.scheme;
    let prefix = cli.prefix;
    // BIP39 entropy: 12 words = 16 bytes, 24 words = 32 bytes.
    let entropy_len = cli.words as usize * 4 / 3;

    let found = Arc::new(AtomicBool::new(false));
    let tries = Arc::new(AtomicU64::new(0));
    let winner: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    eprintln!(
        "Searching: scheme={scheme} prefix={prefix} words={} pattern=/{pattern}/ threads={nthreads}",
        cli.words
    );
    let start = Instant::now();

    let mut handles = Vec::with_capacity(nthreads);
    for _ in 0..nthreads {
        let found = found.clone();
        let tries = tries.clone();
        let winner = winner.clone();
        let re = re.clone();
        handles.push(thread::spawn(move || {
            // Cryptographically secure per-thread RNG seeded from the OS. These
            // are real keys — never use a non-crypto PRNG here.
            let mut rng = ChaCha20Rng::from_entropy();
            let secp = Secp256k1::signing_only();
            let mut buf = [0u8; 32];
            let entropy = &mut buf[..entropy_len];

            while !found.load(Ordering::Relaxed) {
                rng.fill_bytes(entropy);
                if let Some(addr) = derive_address(entropy, scheme, prefix, &secp) {
                    tries.fetch_add(1, Ordering::Relaxed);
                    if re.is_match(&addr) {
                        if !found.swap(true, Ordering::SeqCst) {
                            *winner.lock().unwrap() = Some(entropy.to_vec());
                        }
                        break;
                    }
                }
            }
        }));
    }

    // Detached stats thread: prints a one-line throughput report each second.
    {
        let found = found.clone();
        let tries = tries.clone();
        thread::spawn(move || {
            let mut last = 0u64;
            while !found.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(1));
                let now = tries.load(Ordering::Relaxed);
                let rate = now.saturating_sub(last);
                last = now;
                eprint!(
                    "\r{:>15} tried | {:>10}/s | {:>7.0}s   ",
                    now,
                    rate,
                    start.elapsed().as_secs_f64()
                );
                let _ = std::io::stderr().flush();
            }
        });
    }

    for h in handles {
        let _ = h.join();
    }
    eprintln!();

    let entropy = winner.lock().unwrap().take().expect("winner entropy set");
    let secp = Secp256k1::signing_only();
    let addr = derive_address(&entropy, scheme, prefix, &secp).expect("re-derive address");
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("entropy -> mnemonic");

    let total = tries.load(Ordering::Relaxed);
    eprintln!(
        "Found after {} attempts in {:.1}s ({:.0}/s avg)",
        total,
        start.elapsed().as_secs_f64(),
        total as f64 / start.elapsed().as_secs_f64().max(1e-9),
    );
    println!("Scheme:   {scheme}");
    println!("Prefix:   {prefix}");
    println!("Address:  {addr}");
    println!("Mnemonic: {mnemonic}");
}

fn run_verify(phrase: &str, scheme: Scheme, prefix: u16) {
    let m = Mnemonic::parse(phrase).unwrap_or_else(|e| {
        eprintln!("invalid mnemonic: {e}");
        std::process::exit(2);
    });
    let entropy = m.to_entropy();
    let secp = Secp256k1::signing_only();
    match derive_address(&entropy, scheme, prefix, &secp) {
        Some(addr) => {
            println!("Scheme:   {scheme}");
            println!("Prefix:   {prefix}");
            println!("Address:  {addr}");
        }
        None => {
            eprintln!("derivation failed for this mnemonic");
            std::process::exit(1);
        }
    }
}

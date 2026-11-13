// SPDX-License-Identifier: MIT

//! The BIP39 owner identity (SPEC 3.1): 256-bit entropy to a 24-word English mnemonic and back,
//! the PBKDF2 seed, and the owner Ed25519 and X25519 keys derived from it with HKDF-SHA256.

use std::collections::HashMap;
use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use sha2::Sha512;
use unicode_normalization::UnicodeNormalization;
use x25519_dalek::StaticSecret;

use crate::crypto::{ct_eq, hkdf_32, sha256, x25519_public};
use crate::error::AvpError;

/// The BIP39 English wordlist, a byte copy of the upstream file (SPEC 3.1).
const WORDLIST: &str = include_str!("../../../../vectors/bip39-english.txt");

/// AVP mnemonics are always 24 words over 32 bytes of entropy (SPEC 3.1).
const WORD_COUNT: usize = 24;

/// HKDF info label of the owner Ed25519 signing seed (SPEC 3.1).
pub const OWNER_ED25519_INFO: &[u8] = b"avp/owner/ed25519/v1";

/// HKDF info label of the owner X25519 private key (SPEC 3.1).
pub const OWNER_X25519_INFO: &[u8] = b"avp/owner/x25519/v1";

struct Words {
    list: [&'static str; 2048],
    index: HashMap<&'static str, u16>,
}

fn words() -> &'static Words {
    static WORDS: OnceLock<Words> = OnceLock::new();
    WORDS.get_or_init(|| {
        let mut list = [""; 2048];
        let mut index = HashMap::with_capacity(2048);
        for ((slot, word), i) in list.iter_mut().zip(WORDLIST.lines()).zip(0u16..) {
            *slot = word;
            index.insert(word, i);
        }
        Words { list, index }
    })
}

/// Reads bit `bit` (most significant first) of `bytes`; bits past the end read as zero.
fn bit_at(bytes: &[u8], bit: usize) -> u16 {
    let byte = bytes.get(bit / 8).copied().unwrap_or(0);
    u16::from((byte >> (7 - (bit % 8))) & 1)
}

/// Encodes 32 bytes of entropy as a 24-word BIP39 mnemonic (SPEC 3.1).
///
/// The first 8 bits of `SHA-256(entropy)` are appended as a checksum, the 264 bits are split into
/// 24 groups of 11 bits, most significant first, and each group indexes the English wordlist.
/// Words are joined by one space.
#[must_use]
pub fn entropy_to_mnemonic(entropy: &[u8; 32]) -> String {
    let mut bits = [0u8; 33];
    for (dst, src) in bits
        .iter_mut()
        .zip(entropy.iter().chain(sha256(entropy).iter().take(1)))
    {
        *dst = *src;
    }
    let list = &words().list;
    let mut out = Vec::with_capacity(WORD_COUNT);
    for w in 0..WORD_COUNT {
        let idx = (0..11).fold(0usize, |acc, b| (acc << 1) | usize::from(bit_at(&bits, w * 11 + b)));
        // idx has 11 bits, so it is always below 2048.
        out.push(list.get(idx).copied().unwrap_or_default());
    }
    out.join(" ")
}

/// Decodes a 24-word BIP39 mnemonic back to its 32 bytes of entropy (SPEC 3.1).
///
/// The phrase is NFKD-normalized and split on single spaces.
///
/// # Errors
///
/// [`AvpError::BadEncoding`] if the phrase is not exactly 24 words or holds a word that is not in
/// the list (an empty word from a doubled space included); [`AvpError::BadChecksum`] if the
/// checksum does not match.
pub fn mnemonic_to_entropy(mnemonic: &str) -> Result<[u8; 32], AvpError> {
    let normalized: String = mnemonic.nfkd().collect();
    let parts: Vec<&str> = normalized.split(' ').collect();
    if parts.len() != WORD_COUNT {
        return Err(AvpError::BadEncoding(format!(
            "mnemonic must be exactly 24 words, got {}",
            parts.len()
        )));
    }
    let index = &words().index;
    let mut bits = [0u8; 33];
    for (w, word) in parts.iter().enumerate() {
        let idx = *index
            .get(word)
            .ok_or_else(|| AvpError::BadEncoding(format!("mnemonic has an unknown word at position {}", w + 1)))?;
        for b in 0..11 {
            if (idx >> (10 - b)) & 1 == 1 {
                let bit = w * 11 + b;
                if let Some(byte) = bits.get_mut(bit / 8) {
                    *byte |= 0x80 >> (bit % 8);
                }
            }
        }
    }
    let (entropy, checksum_bits) = bits.split_first_chunk::<32>().ok_or(AvpError::BadChecksum)?;
    let [first, ..] = sha256(entropy);
    if !ct_eq(&[first], checksum_bits) {
        return Err(AvpError::BadChecksum);
    }
    Ok(*entropy)
}

/// The BIP39 seed (SPEC 3.1): `PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic" || NFKD(passphrase),
/// 2048, 64)`.
///
/// AVP uses an empty passphrase; the parameter exists for the reference vectors.
#[must_use]
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let password: String = mnemonic.nfkd().collect();
    let salt: String = "mnemonic".chars().chain(passphrase.nfkd()).collect();
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), salt.as_bytes(), 2048, &mut seed);
    seed
}

/// The owner keys derived from a BIP39 seed (SPEC 3.1).
#[derive(Clone)]
pub struct OwnerKeys {
    /// The owner Ed25519 signing key; its public key is the `ownerKey`.
    pub signing: SigningKey,
    /// The owner X25519 private key.
    pub x25519: StaticSecret,
}

impl OwnerKeys {
    /// Derives the owner keys from a 64-byte BIP39 seed, each as `HKDF-SHA256(ikm = seed, salt =
    /// empty, info = label, L = 32)`.
    ///
    /// # Errors
    ///
    /// [`AvpError::Crypto`] if HKDF fails (not reachable for 32-byte outputs).
    pub fn from_seed(seed: &[u8; 64]) -> Result<OwnerKeys, AvpError> {
        let ed = hkdf_32(seed, &[], OWNER_ED25519_INFO)?;
        let x = hkdf_32(seed, &[], OWNER_X25519_INFO)?;
        Ok(OwnerKeys {
            signing: SigningKey::from_bytes(&ed),
            x25519: StaticSecret::from(x),
        })
    }

    /// Derives the owner keys from the mnemonic entropy: the mnemonic, its empty-passphrase seed,
    /// then [`OwnerKeys::from_seed`].
    ///
    /// # Errors
    ///
    /// As [`OwnerKeys::from_seed`].
    pub fn from_entropy(entropy: &[u8; 32]) -> Result<OwnerKeys, AvpError> {
        OwnerKeys::from_seed(&mnemonic_to_seed(&entropy_to_mnemonic(entropy), ""))
    }

    /// The `ownerKey`: the raw Ed25519 public key.
    #[must_use]
    pub fn owner_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The owner's raw X25519 public key.
    #[must_use]
    pub fn x25519_public(&self) -> [u8; 32] {
        x25519_public(&self.x25519)
    }
}

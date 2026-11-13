// SPDX-License-Identifier: MIT

//! The canonical encoding writer (SPEC 4.1), the wire base64 forms (SPEC 2), and the serde helpers
//! the wire types use.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::AvpError;

/// Writer for the canonical encoding (SPEC 4.1).
///
/// Each method appends one item and returns the writer; [`Ce::finish`] returns the concatenation.
/// A tag that contains `0x00`, or a length or count that does not fit in a `u32`, is recorded and
/// makes [`Ce::finish`] fail, so the writer never produces an ambiguous encoding.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), avp::AvpError> {
/// let mut w = avp::encoding::Ce::new("t");
/// w.str("ab").i64(2).bool(true);
/// assert_eq!(w.finish()?, b"t\0\0\0\0\x02ab\0\0\0\0\0\0\0\x02\x01");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ce {
    buf: Vec<u8>,
    error: Option<&'static str>,
}

impl Ce {
    /// Starts a CE string with `tag(label)`: the UTF-8 bytes of `label`, then one `0x00`.
    #[must_use]
    pub fn new(tag: &str) -> Ce {
        let mut buf = Vec::with_capacity(tag.len() + 64);
        buf.extend_from_slice(tag.as_bytes());
        buf.push(0);
        let error = tag.as_bytes().contains(&0).then_some("CE tag label contains 0x00");
        Ce { buf, error }
    }

    /// Appends `bytes(b)`: `u32BE(len(b)) || b`.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.count(b.len());
        self.buf.extend_from_slice(b);
        self
    }

    /// Appends `str(s)`: `bytes(UTF8(s))`.
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// Appends `i64(n)`: the 8-byte big-endian two's-complement encoding of `n`.
    pub fn i64(&mut self, n: i64) -> &mut Self {
        self.buf.extend_from_slice(&n.to_be_bytes());
        self
    }

    /// Appends `bool(b)`: one byte, `0x00` for false and `0x01` for true.
    pub fn bool(&mut self, b: bool) -> &mut Self {
        self.buf.push(u8::from(b));
        self
    }

    /// Appends `count(n)`: `u32BE(n)`.
    pub fn count(&mut self, n: usize) -> &mut Self {
        match u32::try_from(n) {
            Ok(v) => self.buf.extend_from_slice(&v.to_be_bytes()),
            Err(_) => self.error = Some("CE length or count exceeds u32"),
        }
        self
    }

    /// Returns the finished CE byte string.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadEncoding`] if the tag contained `0x00` or a length or count exceeded `u32`.
    pub fn finish(self) -> Result<Vec<u8>, AvpError> {
        match self.error {
            Some(e) => Err(AvpError::BadEncoding(e.into())),
            None => Ok(self.buf),
        }
    }
}

/// Returns `items` sorted by `key` compared as unsigned bytes (SPEC 2).
///
/// # Errors
///
/// [`AvpError::BadEncoding`] if two items share a key: a duplicate makes the wire form malformed
/// (SPEC 4.2, 4.3).
pub(crate) fn sorted_unique<'a, T, K>(
    items: &'a [T],
    key: impl Fn(&T) -> &K,
    what: &str,
) -> Result<Vec<&'a T>, AvpError>
where
    K: Ord + ?Sized,
{
    let mut out: Vec<&T> = items.iter().collect();
    out.sort_by(|a, b| key(a).cmp(key(b)));
    if out.windows(2).any(|w| matches!(w, [a, b] if key(a) == key(b))) {
        return Err(AvpError::BadEncoding(format!("duplicate {what}")));
    }
    Ok(out)
}

/// Encodes bytes as standard base64 with padding (SPEC 2), the wire form of binary fields.
#[must_use]
pub fn b64_encode(b: &[u8]) -> String {
    STANDARD.encode(b)
}

/// Decodes standard base64 with padding (SPEC 2).
///
/// # Errors
///
/// [`AvpError::BadEncoding`] if the text is not canonical standard base64.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, AvpError> {
    STANDARD
        .decode(s)
        .map_err(|e| AvpError::BadEncoding(format!("base64: {e}")))
}

/// Decodes standard base64 that must hold exactly `N` bytes.
///
/// # Errors
///
/// [`AvpError::BadEncoding`] if the text is not base64 or decodes to another length.
pub fn b64_decode_array<const N: usize>(s: &str) -> Result<[u8; N], AvpError> {
    let v = b64_decode(s)?;
    let len = v.len();
    v.try_into()
        .map_err(|_| AvpError::BadEncoding(format!("expected {N} bytes, got {len}")))
}

/// Encodes bytes as base64url without padding (SPEC 2), used for `repoId` and token text.
#[must_use]
pub fn b64url_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Decodes base64url without padding (SPEC 2).
///
/// # Errors
///
/// [`AvpError::BadEncoding`] if the text is not canonical base64url-nopad.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, AvpError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| AvpError::BadEncoding(format!("base64url: {e}")))
}

/// Serde helper for a variable-length binary field as standard base64 (`#[serde(with = "...")]`).
pub mod b64 {
    use serde::de::Error as _;

    use super::{Deserialize, Deserializer, Serializer, b64_decode, b64_encode};

    /// Serializes bytes as standard base64.
    ///
    /// # Errors
    ///
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64_encode(v))
    }

    /// Deserializes standard base64 into bytes.
    ///
    /// # Errors
    ///
    /// Fails if the value is not a string of canonical standard base64.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        b64_decode(&text).map_err(D::Error::custom)
    }
}

/// Serde helper for a fixed-length binary field as standard base64; any other length is rejected.
pub mod b64_array {
    use serde::de::Error as _;

    use super::{Deserialize, Deserializer, Serializer, b64_decode_array, b64_encode};

    /// Serializes a fixed-length byte array as standard base64.
    ///
    /// # Errors
    ///
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64_encode(v))
    }

    /// Deserializes standard base64 that must decode to exactly `N` bytes.
    ///
    /// # Errors
    ///
    /// Fails if the value is not base64 or has another length.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(d)?;
        b64_decode_array(&text).map_err(D::Error::custom)
    }
}

/// Serde helper for a list of 32-byte ids (commit ids, manifest hashes) as standard base64.
pub mod b64_ids {
    use serde::de::Error as _;
    use serde::ser::SerializeSeq as _;

    use super::{Deserialize, Deserializer, Serializer, b64_decode_array, b64_encode};

    /// Serializes a list of 32-byte ids.
    ///
    /// # Errors
    ///
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for id in v {
            seq.serialize_element(&b64_encode(id))?;
        }
        seq.end()
    }

    /// Deserializes a list of base64 strings that must each decode to exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// Fails if an element is not base64 or has another length.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        let texts = Vec::<String>::deserialize(d)?;
        texts
            .iter()
            .map(|t| b64_decode_array(t).map_err(D::Error::custom))
            .collect()
    }
}

/// The `"v": 2` marker of payload v2 (SPEC 5) and of the tokens (SPEC 11.1).
///
/// It serializes as the number `2` and deserializes only from the number `2`, so a payload or token
/// with any other `v` fails to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct V2;

impl Serialize for V2 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(2)
    }
}

impl<'de> Deserialize<'de> for V2 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match u64::deserialize(d)? {
            2 => Ok(V2),
            v => Err(D::Error::custom(format!("v must be 2, got {v}"))),
        }
    }
}

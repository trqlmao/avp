// SPDX-License-Identifier: MIT

//! Payload v2 (SPEC 5): the per-account, per-field merge, the deletion rule, refresh-token
//! stripping (SPEC 5.1), and the hybrid logical clock that stamps every write.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::encoding::V2;
use crate::error::AvpError;

/// The fields SPEC 5.1 strips when the refresh-token policy is not `true`.
pub const REFRESH_FIELDS: [&str; 2] = ["refreshToken", "expiresAt"];

/// A write stamp `(at, n, by)` (SPEC 5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Stamp {
    /// Epoch milliseconds.
    #[serde(rename = "at")]
    pub at: i64,
    /// The counter within one millisecond.
    #[serde(rename = "n")]
    pub n: i64,
    /// The writer's member id.
    #[serde(rename = "by")]
    pub by: String,
}

impl Stamp {
    /// Orders by `at`, then `n`, then `by` compared by its UTF-8 bytes (SPEC 5).
    #[must_use]
    pub fn order(&self, other: &Stamp) -> Ordering {
        (self.at, self.n, self.by.as_bytes()).cmp(&(other.at, other.n, other.by.as_bytes()))
    }
}

/// One last-writer-wins register: a JSON value and its stamp (SPEC 5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Field {
    /// The value; any JSON, `null` included.
    #[serde(rename = "value", default)]
    pub value: Value,
    /// Epoch milliseconds of the stamp.
    #[serde(rename = "at")]
    pub at: i64,
    /// The stamp counter.
    #[serde(rename = "n")]
    pub n: i64,
    /// The writer's member id.
    #[serde(rename = "by")]
    pub by: String,
}

impl Field {
    /// The field's stamp.
    #[must_use]
    pub fn stamp(&self) -> Stamp {
        Stamp {
            at: self.at,
            n: self.n,
            by: self.by.clone(),
        }
    }

    fn order(&self, other: &Field) -> Ordering {
        (self.at, self.n, self.by.as_bytes()).cmp(&(other.at, other.n, other.by.as_bytes()))
    }

    fn order_stamp(&self, s: &Stamp) -> Ordering {
        (self.at, self.n, self.by.as_bytes()).cmp(&(s.at, s.n, s.by.as_bytes()))
    }
}

/// One account: its optional deletion marker, its fields, and its bans keyed by server id (SPEC 5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Account {
    /// The deletion marker.
    #[serde(rename = "deleted", default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<Stamp>,
    /// The fields by name.
    #[serde(rename = "fields", default)]
    pub fields: BTreeMap<String, Field>,
    /// The latest ban observation per server id.
    #[serde(rename = "bans", default)]
    pub bans: BTreeMap<String, Field>,
}

impl Account {
    /// Whether the account is deleted (SPEC 5): `deleted` exists and is greater than every field
    /// stamp and every ban stamp in the account.
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        match &self.deleted {
            None => false,
            Some(d) => self
                .fields
                .values()
                .chain(self.bans.values())
                .all(|f| f.order_stamp(d) == Ordering::Less),
        }
    }
}

/// The plaintext inside a commit's ciphertext (SPEC 5).
///
/// `v` deserializes only from `2`, so a payload of another version does not decode and is
/// unreadable.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PayloadV2 {
    /// Always `2`.
    #[serde(rename = "v")]
    pub v: V2,
    /// The accounts by player UUID.
    #[serde(rename = "accounts")]
    pub accounts: BTreeMap<String, Account>,
}

impl PayloadV2 {
    /// Decodes a payload from its UTF-8 JSON plaintext.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadEncoding`] if it is not JSON of the payload v2 shape or its `v` is not `2`.
    pub fn from_json(bytes: &[u8]) -> Result<PayloadV2, AvpError> {
        serde_json::from_slice(bytes).map_err(|e| AvpError::BadEncoding(format!("payload: {e}")))
    }

    /// Encodes the payload as compact UTF-8 JSON, map keys sorted.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadEncoding`] if serialization fails (not reachable for this type).
    pub fn to_json(&self) -> Result<Vec<u8>, AvpError> {
        serde_json::to_vec(self).map_err(|e| AvpError::BadEncoding(format!("payload: {e}")))
    }

    /// Removes the `refreshToken` and `expiresAt` fields, stamps included, from every account
    /// (SPEC 5.1).
    pub fn strip_refresh(&mut self) {
        for a in self.accounts.values_mut() {
            for f in REFRESH_FIELDS {
                a.fields.remove(f);
            }
        }
    }

    /// Every stamp in the payload: each field, ban, and deletion marker, for [`Hlc::observe`].
    pub fn stamps(&self) -> impl Iterator<Item = Stamp> + '_ {
        self.accounts.values().flat_map(|a| {
            a.fields
                .values()
                .chain(a.bans.values())
                .map(Field::stamp)
                .chain(a.deleted.iter().cloned())
        })
    }
}

/// Merges one register map into `into`, keeping the field with the greatest stamp per key.
fn merge_registers(into: &mut BTreeMap<String, Field>, from: &BTreeMap<String, Field>) {
    for (k, f) in from {
        match into.get(k) {
            Some(cur) if f.order(cur) != Ordering::Greater => {}
            _ => {
                into.insert(k.clone(), f.clone());
            }
        }
    }
}

/// Merges payloads (SPEC 5): the union of the accounts; per account, each field name and each ban
/// server id takes the field with the greatest stamp; `deleted` is the greatest deletion stamp and
/// is absent if no input has one.
///
/// The merge is commutative, associative, and idempotent. Merging no payloads gives an empty one.
#[must_use]
pub fn merge(payloads: &[PayloadV2]) -> PayloadV2 {
    let mut out = PayloadV2::default();
    for p in payloads {
        for (uuid, a) in &p.accounts {
            let cur = out.accounts.entry(uuid.clone()).or_default();
            if let Some(d) = &a.deleted {
                let greater = cur.deleted.as_ref().is_none_or(|c| d.order(c) == Ordering::Greater);
                if greater {
                    cur.deleted = Some(d.clone());
                }
            }
            merge_registers(&mut cur.fields, &a.fields);
            merge_registers(&mut cur.bans, &a.bans);
        }
    }
    out
}

/// A hybrid logical clock with state `(at, n)` (SPEC 5).
///
/// A client observes every stamp of every payload it merges before its next tick, so each stamp it
/// writes exceeds every stamp it has seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hlc {
    /// The clock's milliseconds.
    pub at: i64,
    /// The clock's counter.
    pub n: i64,
}

impl Hlc {
    /// Advances the clock for a write: `(now, 0)` if `now > at`, otherwise `(at, n + 1)`, and
    /// returns the write's stamp with `by` as the writer.
    ///
    /// A counter at `i64::MAX` cannot grow, so the clock then moves to `(at + 1, 0)` instead, which
    /// still issues a greater stamp.
    pub fn tick(&mut self, now_ms: i64, by: &str) -> Stamp {
        if now_ms > self.at {
            self.at = now_ms;
            self.n = 0;
        } else if let Some(n) = self.n.checked_add(1) {
            self.n = n;
        } else {
            self.at = self.at.saturating_add(1);
            self.n = 0;
        }
        Stamp {
            at: self.at,
            n: self.n,
            by: by.to_string(),
        }
    }

    /// Folds in a stamp seen in a merged payload: a later `at` is taken with its `n`; an equal
    /// `at` takes the larger `n`; an earlier one changes nothing.
    pub fn observe(&mut self, s: &Stamp) {
        match s.at.cmp(&self.at) {
            Ordering::Greater => {
                self.at = s.at;
                self.n = s.n;
            }
            Ordering::Equal => self.n = self.n.max(s.n),
            Ordering::Less => {}
        }
    }
}

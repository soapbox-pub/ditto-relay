//! NIP-45 HyperLogLog: 256 registers sketching the distinct authors of the
//! events counted, so clients can merge counts from several relays without
//! counting an event twice.
//!
//! Which byte of a pubkey picks the register depends on the filter: an
//! `offset` derived from its first tag value, so every relay sketches the
//! same query the same way.

use sha2::{Digest, Sha256};

use crate::event::is_hex64;

pub const REGISTERS: usize = 256;

pub type Registers = [u8; REGISTERS];

/// The offset for a filter whose first tag's first value is `value`.
pub fn offset(value: &str) -> usize {
    let hashed;
    let hex = if is_hex64(value) {
        value
    } else if let Some(pubkey) = address_pubkey(value) {
        pubkey
    } else {
        hashed = hex::encode(Sha256::digest(value));
        &hashed
    };
    let digit = char::from(hex.as_bytes()[32])
        .to_digit(16)
        .expect("hex digits");
    8 + digit as usize
}

/// The pubkey of a NIP-01 address, `<kind>:<pubkey>:<d>`.
fn address_pubkey(value: &str) -> Option<&str> {
    let mut parts = value.splitn(3, ':');
    let kind = parts.next()?;
    let pubkey = parts.next()?;
    parts.next()?;
    (kind.parse::<u16>().is_ok() && is_hex64(pubkey)).then_some(pubkey)
}

/// Count an author in. Returns whether a register grew.
pub fn add(registers: &mut Registers, offset: usize, pubkey: &[u8; 32]) -> bool {
    let index = usize::from(pubkey[offset]);
    // Leading zeros of the 56 bits after the register's byte.
    let mut zeros = 0;
    for &byte in &pubkey[offset + 1..offset + 8] {
        zeros += byte.leading_zeros();
        if byte != 0 {
            break;
        }
    }
    let rank = zeros as u8 + 1;
    let grew = rank > registers[index];
    registers[index] = registers[index].max(rank);
    grew
}

/// Fold `other` into `registers`.
pub fn merge(registers: &mut Registers, other: &[u8]) {
    for (register, &value) in registers.iter_mut().zip(other) {
        *register = (*register).max(value);
    }
}

/// An estimate of how many distinct authors a sketch has seen.
#[cfg(test)]
pub fn estimate(registers: &Registers) -> f64 {
    let m = REGISTERS as f64;
    let sum: f64 = registers.iter().map(|&r| 2f64.powi(-i32::from(r))).sum();
    let raw = 0.7213 / (1.0 + 1.079 / m) * m * m / sum;
    let zeros = registers.iter().filter(|&&r| r == 0).count();
    if raw <= 2.5 * m && zeros > 0 {
        m * (m / zeros as f64).ln()
    } else {
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_offsets_like_nip45() {
        // The 33rd hex digit, plus 8.
        let id = format!("{}f{}", "0".repeat(32), "0".repeat(31));
        assert_eq!(offset(&id), 23);
        let pubkey = format!("{}3{}", "a".repeat(32), "a".repeat(31));
        assert_eq!(offset(&format!("30023:{pubkey}:my:article")), 11);
        let hashed = hex::encode(Sha256::digest("nostr"));
        let digit = char::from(hashed.as_bytes()[32]).to_digit(16).unwrap() as usize;
        assert_eq!(offset("nostr"), 8 + digit);
        // Not an address: hashed.
        assert_eq!(
            offset(&format!("x:{pubkey}:d")),
            offset(&format!("x:{pubkey}:d"))
        );
        assert!((8..24).contains(&offset(&format!("x:{pubkey}:d"))));
    }

    #[test]
    fn ranks_by_leading_zeros_after_the_register() {
        let mut registers = [0; REGISTERS];
        let mut pubkey = [0xff; 32];
        pubkey[8] = 5;
        pubkey[9] = 0;
        pubkey[10] = 0b0001_0000;
        assert!(add(&mut registers, 8, &pubkey));
        assert_eq!(registers[5], 8 + 3 + 1);
        assert!(!add(&mut registers, 8, &pubkey));
        // All zeros: 56 of them.
        let mut zero = [0; 32];
        zero[8] = 6;
        add(&mut registers, 8, &zero);
        assert_eq!(registers[6], 57);
    }

    #[test]
    fn estimates_distinct_authors() {
        let mut registers = [0; REGISTERS];
        for n in 0..10_000u32 {
            let pubkey: [u8; 32] = Sha256::digest(n.to_be_bytes()).into();
            add(&mut registers, 10, &pubkey);
            add(&mut registers, 10, &pubkey);
        }
        let estimate = estimate(&registers);
        assert!((9_000.0..11_000.0).contains(&estimate), "{estimate}");
        let mut merged = [0; REGISTERS];
        merge(&mut merged, &registers);
        assert_eq!(merged, registers);
    }
}

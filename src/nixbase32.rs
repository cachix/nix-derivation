//! Nix's custom base32 encoding used by store-path identities.

use std::cmp::Ordering;

use thiserror::Error;

const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

const fn reverse_table() -> [u8; 256] {
    let mut table = [u8::MAX; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

const REVERSE: [u8; 256] = reverse_table();

/// An invalid Nix base32 string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// The encoded length cannot represent a whole number of bytes.
    #[error("invalid nixbase32 length {0}")]
    InvalidLength(usize),
    /// A byte is not part of Nix's lowercase base32 alphabet.
    #[error("invalid nixbase32 byte {byte:#04x} at offset {offset}")]
    InvalidByte { offset: usize, byte: u8 },
    /// Bits outside the decoded byte sequence are nonzero.
    #[error("nonzero padding bits in nixbase32 input")]
    NonZeroPadding,
}

/// Number of Nix base32 characters required to encode `n` bytes.
#[must_use]
pub const fn encoded_len(n: usize) -> usize {
    n.saturating_mul(8).div_ceil(5)
}

/// Encode bytes using Nix's base32 alphabet and bit ordering.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let len = encoded_len(bytes.len());
    let mut out = String::with_capacity(len);
    for n in (0..len).rev() {
        let bit = n * 5;
        let i = bit / 8;
        let shift = bit % 8;
        let low = u16::from(bytes[i]) >> shift;
        let high = if i + 1 < bytes.len() {
            u16::from(bytes[i + 1]) << (8 - shift)
        } else {
            0
        };
        out.push(ALPHABET[((low | high) & 0x1f) as usize] as char);
    }
    out
}

/// Encode into a caller-selected fixed-width buffer without allocating.
pub(crate) fn encode_fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
    assert_eq!(N, encoded_len(bytes.len()));
    let mut out = [0; N];
    for (index, n) in (0..N).rev().enumerate() {
        let bit = n * 5;
        let i = bit / 8;
        let shift = bit % 8;
        let low = u16::from(bytes[i]) >> shift;
        let high = if i + 1 < bytes.len() {
            u16::from(bytes[i + 1]) << (8 - shift)
        } else {
            0
        };
        out[index] = ALPHABET[((low | high) & 0x1f) as usize];
    }
    out
}

/// Compare equal-width byte strings by their encoded representation without
/// allocating either encoding.
pub(crate) fn cmp_encoded(left: &[u8], right: &[u8]) -> Ordering {
    debug_assert_eq!(left.len(), right.len());
    let len = encoded_len(left.len());
    for n in (0..len).rev() {
        let bit = n * 5;
        let i = bit / 8;
        let shift = bit % 8;
        let digit = |bytes: &[u8]| {
            let low = u16::from(bytes[i]) >> shift;
            let high = if i + 1 < bytes.len() {
                u16::from(bytes[i + 1]) << (8 - shift)
            } else {
                0
            };
            (low | high) & 0x1f
        };
        match digit(left).cmp(&digit(right)) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

/// Decode a canonical, lowercase Nix base32 byte string.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let decoded_len = input.len().saturating_mul(5) / 8;
    if encoded_len(decoded_len) != input.len() {
        return Err(Error::InvalidLength(input.len()));
    }

    let mut out = vec![0u8; decoded_len];
    for (n, &byte) in input.iter().rev().enumerate() {
        let digit = *REVERSE
            .get(byte as usize)
            .filter(|&&digit| digit != u8::MAX)
            .ok_or(Error::InvalidByte {
                offset: input.len() - 1 - n,
                byte,
            })?;
        let bit = n * 5;
        let i = bit / 8;
        let shift = bit % 8;

        if i >= out.len() {
            if digit != 0 {
                return Err(Error::NonZeroPadding);
            }
            continue;
        }
        out[i] |= digit << shift;
        if shift > 3 {
            let high = digit >> (8 - shift);
            if i + 1 < out.len() {
                out[i + 1] |= high;
            } else if high != 0 {
                return Err(Error::NonZeroPadding);
            }
        }
    }
    Ok(out)
}

/// Decode a value whose output width is known by the caller without an
/// intermediate heap allocation.
pub(crate) fn decode_fixed<const N: usize>(input: &[u8]) -> Result<[u8; N], Error> {
    if encoded_len(N) != input.len() {
        return Err(Error::InvalidLength(input.len()));
    }

    let mut out = [0u8; N];
    for (n, &byte) in input.iter().rev().enumerate() {
        let digit = REVERSE[byte as usize];
        if digit == u8::MAX {
            return Err(Error::InvalidByte {
                offset: input.len() - 1 - n,
                byte,
            });
        }
        let bit = n * 5;
        let i = bit / 8;
        let shift = bit % 8;

        if i >= out.len() {
            if digit != 0 {
                return Err(Error::NonZeroPadding);
            }
            continue;
        }
        out[i] |= digit << shift;
        if shift > 3 {
            let high = digit >> (8 - shift);
            if i + 1 < out.len() {
                out[i + 1] |= high;
            } else if high != 0 {
                return Err(Error::NonZeroPadding);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from `nix-base32` 0.2.0 by Peter Kolloch, licensed
    /// Apache-2.0. They cover every hash width used by Nix, including the
    /// padding bits not exercised by 20-byte store-path digests.
    const VECTORS: &[(&str, &str)] = &[
        (
            "47b2d8f260c2d48116044bc43fe3de0f",
            "0gvvikzi2b0hb83m62c3rdicj7",
        ),
        (
            "1f74d74729abdc08f4f84e8f7f8c808c8ed92ee5",
            "wlpdk3lch267z3sfz3s0ip5b553xfx0z",
        ),
        (
            "a315ab26a0c4829321730c44a26f4497f7da0631402669caa4e24bdcd9db7c87",
            "11vwvgcxqjz2lk56j9j0643dmxwp8ips4i0cfchr70n4l0kan5d3",
        ),
        (
            "296a445bfa5e1990af299ec74582468ab7a77e495861691ff79ab21234e514b64fc72b294d7305ecdd0febaa13b1bc1a3f359a711bb93dfb2b82804c64354dab",
            "2mlsdb49j084azv7nwinwcs6lzimg5i2fmfn3yxxh2p6k995g3lzdhlwls15clsywgnjqaq95zagdwa8s14biwy56pr06ayz9dl8si9",
        ),
    ];

    fn decode_hex(encoded: &str) -> Vec<u8> {
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn round_trips_all_short_lengths() {
        for len in 0..128 {
            let input: Vec<u8> = (0..len).map(|i| (i * 71 + 19) as u8).collect();
            assert_eq!(decode(encode(&input).as_bytes()), Ok(input));
        }
    }

    #[test]
    fn matches_nix_sha256_vector() {
        let digest = [
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
            0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
            0x93, 0x8b, 0x98, 0x24,
        ];
        assert_eq!(
            encode(&digest),
            "094qif9n4cq4fdg459qzbhg1c6wywawwaaivx0k0x8xhbyx4vwic"
        );
    }

    #[test]
    fn matches_known_hash_width_vectors() {
        for &(hex, encoded) in VECTORS {
            let bytes = decode_hex(hex);
            assert_eq!(encode(&bytes), encoded);
            assert_eq!(decode(encoded.as_bytes()), Ok(bytes));
        }
    }

    #[test]
    fn allocation_free_comparison_matches_encoded_strings() {
        for seed in 0..64_u8 {
            let left: Vec<u8> = (0..20)
                .map(|index: u8| seed.wrapping_add(index.wrapping_mul(17)))
                .collect();
            for other in 0..64_u8 {
                let right: Vec<u8> = (0..20)
                    .map(|index: u8| other.wrapping_add(index.wrapping_mul(29)))
                    .collect();
                assert_eq!(
                    cmp_encoded(&left, &right),
                    encode(&left).cmp(&encode(&right))
                );
            }
        }
    }

    #[test]
    fn fixed_width_decode_matches_general_decode() {
        for seed in 0..64_u8 {
            let bytes: [u8; 20] =
                std::array::from_fn(|index| seed.wrapping_add((index as u8).wrapping_mul(31)));
            let encoded = encode(&bytes);
            assert_eq!(decode_fixed::<20>(encoded.as_bytes()), Ok(bytes));
            assert_eq!(decode(encoded.as_bytes()), Ok(bytes.to_vec()));
        }
    }

    #[test]
    fn fixed_width_encode_matches_general_encode() {
        for seed in 0..64_u8 {
            let bytes: [u8; 20] =
                std::array::from_fn(|index| seed.wrapping_add((index as u8).wrapping_mul(31)));
            assert_eq!(
                encode_fixed::<32>(&bytes).as_slice(),
                encode(&bytes).as_bytes()
            );
        }
    }

    #[test]
    fn rejects_noncanonical_inputs() {
        assert_eq!(decode(b""), Ok(Vec::new()));
        assert_eq!(decode(b"0"), Err(Error::InvalidLength(1)));
        assert!(matches!(
            decode(b"0E"),
            Err(Error::InvalidByte { byte: b'E', .. })
        ));
        assert_eq!(decode(b"z0"), Err(Error::NonZeroPadding));
    }
}

//! The recovery code: 160 random bits, Crockford base32, eight groups of four.
//!
//! No checksum. AES-KW's unwrap is authenticated, so a wrong code fails to
//! open the wrap and cannot produce a false positive — a checksum would be a
//! second thing to get wrong for no gain (spec section 9.2).
//!
//! Generation takes its randomness as an argument rather than reading it from
//! the browser, so the formatting is testable on the host. The caller passes
//! bytes from `crypto.getRandomValues`.

/// Bytes of entropy in a code. 20 bytes = 160 bits.
pub const CODE_BYTES: usize = 20;
/// Characters in a normalized code. 160 bits / 5 bits per symbol.
pub const CODE_CHARS: usize = 32;

/// Crockford base32: excludes `I`, `L`, `O` (characters people misread) and
/// `U` (to avoid accidental obscenities).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A candidate recovery code could not be normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    #[error("code is {0} characters after stripping separators, expected {CODE_CHARS}")]
    Length(usize),
    #[error("character `{0}` is not part of the recovery code alphabet")]
    Character(char),
}

/// Reads the 5-bit symbol starting at bit `bit_start`, most significant bit
/// first. Bits are addressed across the whole byte array — since 8 (bits per
/// byte) and 5 (bits per symbol) share no common factor, every symbol but
/// every eighth one straddles a byte boundary.
fn symbol_at(bytes: &[u8; CODE_BYTES], bit_start: usize) -> u8 {
    (0..5).fold(0u8, |acc, offset| {
        let bit = bit_start + offset;
        let bit_value = (bytes[bit / 8] >> (7 - bit % 8)) & 1;
        (acc << 1) | bit_value
    })
}

/// Packs `bytes` into [`CODE_CHARS`] Crockford base32 symbols, most
/// significant bit first, and joins groups of four with `-`.
///
/// `CODE_BYTES * 8` and `CODE_CHARS * 5` are both 160: the two constants are
/// chosen so the bits divide evenly into symbols, with none left over.
pub fn format_code(bytes: &[u8; CODE_BYTES]) -> String {
    (0..CODE_CHARS)
        .map(|i| ALPHABET[symbol_at(bytes, i * 5) as usize] as char)
        .collect::<Vec<char>>()
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("-")
}

/// Maps a character a user might type in place of an excluded lookalike onto
/// the alphabet's actual symbol for it.
fn fold_alias(c: char) -> char {
    match c {
        'I' | 'L' => '1',
        'O' => '0',
        other => other,
    }
}

/// Reverses [`format_code`]: strips whitespace and `-`, folds Crockford
/// aliases, and repacks each alphabet symbol into 5 bits, most significant
/// bit first, to recover the original [`CODE_BYTES`] bytes.
pub fn normalize(input: &str) -> Result<Vec<u8>, RecoveryError> {
    let stripped: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| fold_alias(c.to_ascii_uppercase()))
        .collect();

    if stripped.chars().count() != CODE_CHARS {
        return Err(RecoveryError::Length(stripped.chars().count()));
    }

    let symbols = stripped
        .chars()
        .map(|c| {
            ALPHABET
                .iter()
                .position(|&a| a as char == c)
                .map(|p| p as u8)
                .ok_or(RecoveryError::Character(c))
        })
        .collect::<Result<Vec<u8>, RecoveryError>>()?;

    // Inverse of `symbol_at`: 32 symbols of 5 bits each divide evenly back
    // into 20 bytes, so every bit written below has a home with none left
    // over and no partial byte at the end.
    let mut bytes = [0u8; CODE_BYTES];
    for (i, symbol) in symbols.iter().enumerate() {
        for offset in 0..5 {
            let bit_index = i * 5 + offset;
            if (symbol >> (4 - offset)) & 1 == 1 {
                bytes[bit_index / 8] |= 1 << (7 - bit_index % 8);
            }
        }
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twenty_bytes_become_thirty_two_characters_in_eight_groups() {
        let code = format_code(&[0xAB; CODE_BYTES]);
        assert_eq!(code.len(), CODE_CHARS + 7, "32 chars plus 7 hyphens");
        assert_eq!(code.matches('-').count(), 7);
        for group in code.split('-') {
            assert_eq!(group.len(), 4);
        }
    }

    #[test]
    fn formatting_is_deterministic_and_reversible() {
        let bytes = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let code = format_code(&bytes);
        assert_eq!(normalize(&code).expect("normalize"), bytes.to_vec());
    }

    /// The user reads this off a screen and types it on another device.
    /// Every one of these is a realistic transcription, and all must work.
    #[test]
    fn normalization_accepts_realistic_transcriptions() {
        let bytes = [7u8; CODE_BYTES];
        let canonical = format_code(&bytes);
        let stripped = canonical.replace('-', "");

        for variant in [
            canonical.clone(),
            stripped.clone(),
            stripped.to_lowercase(),
            format!("  {canonical}  "),
            canonical.replace('-', " "),
        ] {
            assert_eq!(
                normalize(&variant).unwrap_or_else(|_| panic!("{variant:?} should normalize")),
                bytes.to_vec()
            );
        }
    }

    /// Crockford base32 folds the characters people confuse. Someone reading
    /// `0` as `O` must still get in.
    #[test]
    fn crockford_aliases_are_folded() {
        let with_zero = "0000-0000-0000-0000-0000-0000-0000-0000";
        let with_oh = "OOOO-OOOO-OOOO-OOOO-OOOO-OOOO-OOOO-OOOO";
        assert_eq!(
            normalize(with_zero).expect("zero"),
            normalize(with_oh).expect("oh")
        );

        let with_one = "1111-1111-1111-1111-1111-1111-1111-1111";
        for alias in ["IIII", "LLLL", "iiii", "llll"] {
            let candidate = [alias; 8].join("-");
            assert_eq!(
                normalize(&candidate).expect("alias"),
                normalize(with_one).expect("one"),
            );
        }
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(matches!(normalize("ABCD"), Err(RecoveryError::Length(4))));
        let too_long = format!("{}A", "0".repeat(CODE_CHARS));
        assert!(matches!(
            normalize(&too_long),
            Err(RecoveryError::Length(33))
        ));
    }

    #[test]
    fn characters_outside_the_alphabet_are_rejected() {
        let bad = format!("U{}", "0".repeat(CODE_CHARS - 1));
        assert!(matches!(
            normalize(&bad),
            Err(RecoveryError::Character('U'))
        ));
    }

    /// 160 bits. Anything less and the "no rate limiting needed" argument in
    /// the spec stops holding.
    #[test]
    fn the_code_carries_one_hundred_and_sixty_bits() {
        assert_eq!(CODE_BYTES * 8, 160);
    }

    /// The one test in this module that a symmetric bit-addressing bug cannot
    /// survive. Every other byte-level test here is a round-trip or an
    /// equivalence check, and both pass happily when `format_code` and
    /// `normalize` are wrong in the same direction. This value was derived three
    /// times independently — by hand in Python, against the standard library's
    /// RFC 4648 base32 with the alphabet remapped, and by bit-shifting — before
    /// being written down.
    #[test]
    fn a_known_input_produces_a_known_code() {
        let bytes: [u8; CODE_BYTES] = core::array::from_fn(|i| (i + 1) as u8);
        assert_eq!(
            format_code(&bytes),
            "0410-6105-0R3G-G28A-1C60-T3GF-208H-44RM"
        );
    }
}

//! Acrostic steganography.

use crate::{
    error::{BxError, BxResult},
    stego::{decode_framed_bits, framed_payload_bits},
};

pub const MAX_INPUT_BYTES: usize = 256;

pub fn encode(input: &[u8], carrier: &str) -> BxResult<String> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(BxError::AcrosticInputTooLarge(input.len()));
    }

    let bits = framed_payload_bits(input)?;
    let word_count = carrier.split_whitespace().count();
    if word_count < bits.len() {
        return Err(BxError::CarrierTooShort {
            need: bits.len(),
            have: word_count,
        });
    }

    let mut encoded_words = Vec::with_capacity(word_count);
    for (word, bit) in carrier.split_whitespace().zip(bits.iter().copied()) {
        encoded_words.push(apply_bit_to_word(word, bit));
    }
    encoded_words.extend(
        carrier
            .split_whitespace()
            .skip(bits.len())
            .map(str::to_string),
    );

    Ok(encoded_words.join(" "))
}

pub fn decode(input: &str) -> BxResult<Vec<u8>> {
    let bits = input
        .split_whitespace()
        .map(bit_from_word)
        .collect::<BxResult<Vec<_>>>()?;

    decode_framed_bits(&bits)
}

fn apply_bit_to_word(word: &str, bit: bool) -> String {
    let mut output = String::with_capacity(word.len());
    let mut encoded = false;

    for ch in word.chars() {
        if !encoded && ch.is_ascii_alphabetic() {
            encoded = true;
            if bit {
                output.push(ch.to_ascii_uppercase());
            } else {
                output.push(ch.to_ascii_lowercase());
            }
        } else {
            output.push(ch);
        }
    }

    output
}

fn bit_from_word(word: &str) -> BxResult<bool> {
    let ch = word
        .chars()
        .find(|ch| ch.is_ascii_alphabetic())
        .ok_or_else(|| {
            BxError::StegoExtract("acrostic carrier word has no ASCII letter".to_string())
        })?;

    Ok(ch.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carrier(word_count: usize) -> String {
        (0..word_count)
            .map(|index| format!("word{index}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn roundtrip_within_limit() -> BxResult<()> {
        let input = b"tiny encrypted blob";
        let encoded = encode(input, &carrier((input.len() + 4) * 8))?;
        let decoded = decode(&encoded)?;

        assert_eq!(decoded, input);
        Ok(())
    }

    #[test]
    fn exactly_256_bytes_succeeds() -> BxResult<()> {
        let input = [3u8; MAX_INPUT_BYTES];
        let encoded = encode(&input, &carrier((input.len() + 4) * 8))?;
        let decoded = decode(&encoded)?;

        assert_eq!(decoded, input);
        Ok(())
    }

    #[test]
    fn two_hundred_fifty_seven_bytes_returns_error() {
        let input = [3u8; MAX_INPUT_BYTES + 1];
        let result = encode(&input, &carrier((input.len() + 4) * 8));

        assert!(matches!(result, Err(BxError::AcrosticInputTooLarge(257))));
    }

    #[test]
    fn carrier_too_short_returns_error() {
        let result = encode(b"abc", &carrier(3));

        assert!(matches!(
            result,
            Err(BxError::CarrierTooShort { need: 56, have: 3 })
        ));
    }

    #[test]
    fn non_wrapped_input_returns_error() {
        let result = decode("plain carrier text only");

        assert!(matches!(result, Err(BxError::StegoExtract(_))));
    }
}

//! Whitespace steganography.

use crate::{
    error::{BxError, BxResult},
    stego::{decode_framed_bits, framed_payload_bits},
};

pub fn encode(input: &[u8]) -> BxResult<String> {
    let mut output = String::with_capacity((input.len() + 4) * 8);

    for bit in framed_payload_bits(input)? {
        output.push(if bit { '\t' } else { ' ' });
    }

    Ok(output)
}

pub fn decode(input: &str) -> BxResult<Vec<u8>> {
    let bits = input
        .bytes()
        .map(|byte| match byte {
            b' ' => Ok(false),
            b'\t' => Ok(true),
            _ => Err(BxError::StegoExtract(
                "whitespace input contains non-stego bytes".to_string(),
            )),
        })
        .collect::<BxResult<Vec<_>>>()?;

    decode_framed_bits(&bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() -> BxResult<()> {
        let encoded = encode(b"")?;
        let decoded = decode(&encoded)?;

        assert!(decoded.is_empty());
        Ok(())
    }

    #[test]
    fn roundtrip_arbitrary_bytes() -> BxResult<()> {
        let input = [0, 1, 2, 3, 127, 128, 254, 255];
        let encoded = encode(&input)?;
        let decoded = decode(&encoded)?;

        assert_eq!(decoded, input);
        Ok(())
    }

    #[test]
    fn roundtrip_large_input() -> BxResult<()> {
        let input = (0..10_240)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let encoded = encode(&input)?;
        let decoded = decode(&encoded)?;

        assert_eq!(decoded, input);
        Ok(())
    }

    #[test]
    fn non_wrapped_input_returns_error() {
        let result = decode("plain text");

        assert!(matches!(result, Err(BxError::StegoExtract(_))));
    }
}

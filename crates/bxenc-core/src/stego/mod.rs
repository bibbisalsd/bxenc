pub mod acrostic;
pub mod whitespace;

use crate::error::{BxError, BxResult};

fn framed_payload_bits(input: &[u8]) -> BxResult<Vec<bool>> {
    let len = u32::try_from(input.len()).map_err(|_| {
        BxError::StegoExtract("stego input is too large to length-frame".to_string())
    })?;
    let mut framed = Vec::with_capacity(4 + input.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend_from_slice(input);

    Ok(bytes_to_bits(&framed))
}

fn decode_framed_bits(bits: &[bool]) -> BxResult<Vec<u8>> {
    if bits.len() < 32 {
        return Err(BxError::StegoExtract(
            "stego input is too short to contain a length header".to_string(),
        ));
    }

    let length_bytes = bits_to_bytes(&bits[..32])?;
    let length = u32::from_le_bytes(
        length_bytes
            .as_slice()
            .try_into()
            .map_err(|_| BxError::StegoExtract("invalid length header".to_string()))?,
    ) as usize;
    let needed_bits =
        32usize
            .checked_add(length.checked_mul(8).ok_or_else(|| {
                BxError::StegoExtract("stego length header overflows".to_string())
            })?)
            .ok_or_else(|| BxError::StegoExtract("stego length header overflows".to_string()))?;

    if bits.len() < needed_bits {
        return Err(BxError::StegoExtract(format!(
            "stego input is truncated: need {needed_bits} bits, have {}",
            bits.len()
        )));
    }

    bits_to_bytes(&bits[32..needed_bits])
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |offset| byte & (0x80 >> offset) != 0))
        .collect()
}

fn bits_to_bytes(bits: &[bool]) -> BxResult<Vec<u8>> {
    if !bits.len().is_multiple_of(8) {
        return Err(BxError::StegoExtract(
            "stego bit stream is not byte-aligned".to_string(),
        ));
    }

    Ok(bits
        .chunks_exact(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(0u8, |byte, (offset, bit)| {
                if !bit {
                    return byte;
                }

                byte | (0x80 >> offset)
            })
        })
        .collect())
}

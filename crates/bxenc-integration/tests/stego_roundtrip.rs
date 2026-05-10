use std::error::Error;

use bxenc_core::{
    stego::{acrostic, whitespace},
    BxError,
};

fn carrier(word_count: usize) -> String {
    (0..word_count)
        .map(|index| format!("carrier{index}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn whitespace_and_acrostic_roundtrip() -> Result<(), Box<dyn Error>> {
    let input = b"tiny stego payload";

    let whitespace_encoded = whitespace::encode(input)?;
    assert_eq!(whitespace::decode(&whitespace_encoded)?, input);

    let acrostic_encoded = acrostic::encode(input, &carrier((input.len() + 4) * 8))?;
    assert_eq!(acrostic::decode(&acrostic_encoded)?, input);

    Ok(())
}

#[test]
fn non_wrapped_inputs_return_errors() {
    let whitespace_result = whitespace::decode("this is not wrapped");
    let acrostic_result = acrostic::decode("this is not wrapped");

    assert!(matches!(whitespace_result, Err(BxError::StegoExtract(_))));
    assert!(matches!(acrostic_result, Err(BxError::StegoExtract(_))));
}

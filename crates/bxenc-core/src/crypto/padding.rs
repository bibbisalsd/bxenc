//! PADMÉ (Padding Arbitrary Data with Maximal Efficiency) implementation.
//! Based on the PURBs (Padded Uniform Random Blobs) padding scheme.
//! This scheme leaks only O(log log L) bits of the payload length L.

pub fn padme_len(len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    // e = floor(log2(len))
    let e = 63 - (len as u64).leading_zeros();

    // s = floor(log2(e + 1))
    let s = 63 - ((e + 1) as u64).leading_zeros();

    let step = 1 << (e - s);
    len.div_ceil(step) * step
}

/// Clamps the length to the next operational bucket: 256, 512, 1024, 2048, 4096.
pub fn clamp_to_bucket(len: usize) -> usize {
    if len <= 256 {
        256
    } else if len <= 512 {
        512
    } else if len <= 1024 {
        1024
    } else if len <= 2048 {
        2048
    } else if len <= 4096 {
        4096
    } else {
        padme_len(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padme_len() {
        // Test some known values
        assert_eq!(padme_len(0), 0);
        assert_eq!(padme_len(1), 1);
        assert_eq!(padme_len(100), 112); // e=6, s=2, step=16, ceil(100/16)*16 = 7*16 = 112
        assert_eq!(padme_len(500), 512); // e=8, s=3, step=32, ceil(500/32)*32 = 16*32 = 512
        assert_eq!(padme_len(1000), 1024); // e=9, s=3, step=64, ceil(1000/64)*64 = 16*64 = 1024
        assert_eq!(padme_len(1500), 1536); // e=10, s=3, step=128, ceil(1500/128)*128 = 12*128 = 1536
    }

    #[test]
    fn test_clamp_to_bucket() {
        assert_eq!(clamp_to_bucket(10), 256);
        assert_eq!(clamp_to_bucket(256), 256);
        assert_eq!(clamp_to_bucket(257), 512);
        assert_eq!(clamp_to_bucket(1000), 1024);
        assert_eq!(clamp_to_bucket(1025), 2048);
        assert_eq!(clamp_to_bucket(3000), 4096);
        assert_eq!(clamp_to_bucket(5000), padme_len(5000));
    }
}

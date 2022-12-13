mod keccak;

pub fn sha3_224(bytes: &[u8]) -> Vec<u8> {
  keccak::sponge(bytes, (1600 - 2 * 224) / 8, 224 / 8)
}

pub fn sha3_256(bytes: &[u8]) -> Vec<u8> {
  keccak::sponge(bytes, (1600 - 2 * 256) / 8, 256 / 8)
}

pub fn sha3_384(bytes: &[u8]) -> Vec<u8> {
  keccak::sponge(bytes, (1600 - 2 * 384) / 8, 384 / 8)
}

pub fn sha3_512(bytes: &[u8]) -> Vec<u8> {
  keccak::sponge(bytes, (1600 - 2 * 512) / 8, 512 / 8)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn to_hex_str(bytes: &[u8]) -> String {
    bytes.iter()
      .flat_map(|&b| [b >> 4, b & 0b1111])
      .map(|b| match b {
        0..=9 => (b + b'0') as char,
        10..=16 => (b + b'a' - 10) as char,
        _ => unreachable!(),
      })
      .collect()
  }

  macro_rules! assert_hash_eq {
    ($hash:expr, $result:expr) => {
      assert_eq!(to_hex_str(&$hash), $result)
    };
  }

  #[test]
  fn test_hashes() {
    assert_hash_eq!(sha3_224(b"hello world"), "dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5");
    assert_hash_eq!(sha3_256(b"hello world"), "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938");
    assert_hash_eq!(sha3_384(b"hello world"), "83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b");
    assert_hash_eq!(sha3_512(b"hello world"), "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a");
  }
}

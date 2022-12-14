const RHO: [u32; 24] = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

const PI: [usize; 24] = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

const RC: [u64; 24] = [
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

fn keccac_f(a: &mut [u64; 25]) {
  for i in 0..24 {
    let mut bc = [0; 5];
    for x in 0..5 {
      for y in 0..5 {
        bc[x] ^= a[5*y+x];
      }
    }

    for x in 0..5 {
      for y in 0..5 {
        a[5 * y + x] ^= bc[(x + 4) % 5] ^ bc[(x + 1) % 5].rotate_left(1);
      }
    }

    let mut last = a[1];
    for x in 0..24 {
      (a[PI[x]], last) = (last.rotate_left(RHO[x]), a[PI[x]]);
    }

    for y in 0..5 {
      for x in 0..5 {
        bc[x] = a[y*5 + x];
      }
      for x in 0..5 {
        a[y*5 + x] = bc[x] ^ (!bc[(x+1) % 5] & bc[(x+2) % 5]);
      }
    }

    a[0] ^= RC[i];
  }
}

fn pad_10star1(x: usize, m: usize) -> impl Iterator<Item=u8> {
  let j = ((2*x - m % x) - 2) % x;
  [0x06].iter().chain(std::iter::repeat(&0).take(j)).chain(&[0x80]).copied()
}

pub fn sponge(bytes: &[u8], r: usize, outlen: usize) -> Vec<u8> {
  assert!(outlen < r);

  #[repr(align(8))]
  struct State([u8; 200]);
  let mut state = State([0; 200]);

  let mut content = bytes.iter().copied().chain(pad_10star1(r, bytes.len()));
  for _ in 0..(bytes.len() + r - 1) / r {
    for i in 0..r {
      state.0[i] ^= content.next().unwrap();
    }
    // SAFETY: safe due to State struct ensuring word-alignment.
    keccac_f(unsafe { std::mem::transmute(&mut state.0) });
  }
  state.0[..outlen].to_vec()
}


#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_keccac_f() {
    let mut data = [0u64; 25];
    keccac_f(&mut data);
    assert_eq!(data, [
      0xF1258F7940E1DDE7, 0x84D5CCF933C0478A, 0xD598261EA65AA9EE, 0xBD1547306F80494D,
      0x8B284E056253D057, 0xFF97A42D7F8E6FD4, 0x90FEE5A0A44647C4, 0x8C5BDA0CD6192E76,
      0xAD30A6F71B19059C, 0x30935AB7D08FFC64, 0xEB5AA93F2317D635, 0xA9A6E6260D712103,
      0x81A57C16DBCF555F, 0x43B831CD0347C826, 0x01F22F1A11A5569F, 0x05E5635A21D9AE61,
      0x64BEFEF28CC970F2, 0x613670957BC46611, 0xB87C5A554FD00ECB, 0x8C3EE88A1CCF32C8,
      0x940C7922AE3A2614, 0x1841F924A2C509E4, 0x16F53526E70465C2, 0x75F644E97F30A13B,
      0xEAF1FF7B5CECA249,
    ]);
    keccac_f(&mut data);
    assert_eq!(data, [
      0x2D5C954DF96ECB3C, 0x6A332CD07057B56D, 0x093D8D1270D76B6C, 0x8A20D9B25569D094,
      0x4F9C4F99E5E7F156, 0xF957B9A2DA65FB38, 0x85773DAE1275AF0D, 0xFAF4F247C3D810F7,
      0x1F1B9EE6F79A8759, 0xE4FECC0FEE98B425, 0x68CE61B6B9CE68A1, 0xDEEA66C4BA8F974F,
      0x33C43D836EAFB1F5, 0xE00654042719DBD9, 0x7CF8A9F009831265, 0xFD5449A6BF174743,
      0x97DDAD33D8994B40, 0x48EAD5FC5D0BE774, 0xE3B8C8EE55B7B03C, 0x91A0226E649E42E9,
      0x900E3129E7BADD7B, 0x202A9EC5FAA3CCE8, 0x5B3402464E1C3DB6, 0x609F4E62A44C1059,
      0x20D06CD26A8FBF5C,
    ]);
  }
}

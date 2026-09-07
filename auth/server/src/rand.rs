//! Random secrets (api key secrets, TOTP secrets, oauth state),
//! read directly from the OS random source ([SysRng]) so they
//! cannot repeat across a `fork` the way a userspace generator's
//! stream can.
//!
//! These panic if the OS random source is unavailable,
//! as does `rand::rng()`.

use rand::{TryRng as _, rngs::SysRng};

const ALPHANUMERIC: &[u8; 62] =
  b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Uniformly random alphanumeric string.
///
/// Reads the OS random source in 64 byte blocks (rather than
/// once per character) and rejection samples 6 bits per byte
/// onto the 62 character alphabet, keeping the distribution
/// uniform.
pub fn random_string(length: usize) -> String {
  let mut out = String::with_capacity(length);
  let mut block = [0u8; 64];
  while out.len() < length {
    SysRng
      .try_fill_bytes(&mut block)
      .expect("OS random source unavailable");
    for byte in block {
      let index = usize::from(byte & 0x3F);
      if index < ALPHANUMERIC.len() {
        out.push(char::from(ALPHANUMERIC[index]));
        if out.len() == length {
          break;
        }
      }
    }
  }
  out
}

/// Uniformly random bytes (full 8 bits of entropy each).
pub fn random_bytes(length: usize) -> Vec<u8> {
  let mut bytes = vec![0u8; length];
  SysRng
    .try_fill_bytes(&mut bytes)
    .expect("OS random source unavailable");
  bytes
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_random_string_length_and_charset() {
    for length in [0, 1, 20, 40, 63, 64, 65, 200] {
      let s = random_string(length);
      assert_eq!(s.len(), length);
      assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }
    // Every alphabet character shows up over a large sample.
    let sample = random_string(20_000);
    for c in ALPHANUMERIC {
      assert!(sample.contains(char::from(*c)));
    }
  }

  #[test]
  fn test_random_bytes_length_and_entropy() {
    assert_eq!(random_bytes(40).len(), 40);
    assert_eq!(random_bytes(0).len(), 0);
    assert_ne!(random_bytes(20), random_bytes(20));
    // Not restricted to the alphanumeric range.
    let bytes = random_bytes(512);
    assert!(bytes.iter().any(|b| !b.is_ascii_alphanumeric()));
  }

  #[test]
  fn test_random_string_unique() {
    assert_ne!(random_string(20), random_string(20));
  }
}

use rand::RngExt as _;

pub fn random_string(length: usize) -> String {
  rand::rng()
    .sample_iter(&rand::distr::Alphanumeric)
    .take(length)
    .map(char::from)
    .collect()
}

pub fn random_bytes(length: usize) -> Vec<u8> {
  rand::rng()
    .sample_iter(&rand::distr::Alphanumeric)
    .take(length)
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_random_string_length_and_charset() {
    for length in [0, 1, 20, 40] {
      let s = random_string(length);
      assert_eq!(s.len(), length);
      assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }
  }

  #[test]
  fn test_random_bytes_length() {
    assert_eq!(random_bytes(40).len(), 40);
  }

  #[test]
  fn test_random_string_unique() {
    assert_ne!(random_string(20), random_string(20));
  }
}

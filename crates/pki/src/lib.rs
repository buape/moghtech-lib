#![doc = include_str!("../README.md")]

mod key;
mod kinds;

pub use key::*;
pub use kinds::*;

#[cfg(feature = "cli")]
pub mod cli;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiKind {
  /// The client has the server public key pinned, and proves its
  /// own public key in a single message, which authenticates
  /// information both sides know (the prologue, such as the
  /// request) without encrypting it.
  ///
  /// Only the server can validate the message, and whoever holds
  /// the server private key can forge one for any client key. The
  /// message can be replayed: bind a timestamp or nonce into the
  /// prologue and enforce a window. See
  /// [one_way::OneWayNoiseHandshake].
  ///
  /// Uses Noise IK handshake.
  /// <https://noiseprotocol.org/noise.html#handshake-patterns>
  OneWay,
  /// Multistep handshake where each side
  /// gains zero trust knowledge of the other's
  /// public key for verification.
  ///
  /// Uses Noise XX handshake.
  /// <https://noiseprotocol.org/noise.html#handshake-patterns>
  Mutual,
}

impl PkiKind {
  const ONE_WAY: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
  const MUTUAL: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
  pub fn noise_params(&self) -> &'static str {
    match self {
      PkiKind::OneWay => Self::ONE_WAY,
      PkiKind::Mutual => Self::MUTUAL,
    }
  }
}

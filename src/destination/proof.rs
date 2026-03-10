//! Proof strategies for destinations
//!
//! This module implements proof strategies that determine how destinations
//! respond to incoming packets.

use std::sync::Arc;

use crate::packet::Packet;

/// Proof strategy for a destination.
/// Values match Python: PROVE_NONE = 0x21, PROVE_APP = 0x22, PROVE_ALL = 0x23
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum ProofStrategy {
    /// Never generate proofs automatically
    #[default]
    None = 0x21,
    /// Let the application decide whether to prove
    App = 0x22,
    /// Always generate proofs for all packets
    All = 0x23,
}


impl From<u8> for ProofStrategy {
    fn from(value: u8) -> Self {
        match value {
            0x21 => ProofStrategy::None,
            0x22 => ProofStrategy::App,
            0x23 => ProofStrategy::All,
            _ => ProofStrategy::None,
        }
    }
}

/// Proof request callback type
pub type ProofRequestCallback = Arc<dyn Fn(&Packet) -> bool + Send + Sync>;

/// Configuration for destination proof handling
#[derive(Default)]
pub struct ProofConfig {
    /// The proof strategy
    pub strategy: ProofStrategy,
    /// Optional callback for PROVE_APP strategy
    pub callback: Option<ProofRequestCallback>,
}

impl ProofConfig {
    /// Create a new proof config with a strategy
    pub fn new(strategy: ProofStrategy) -> Self {
        Self {
            strategy,
            callback: None,
        }
    }

    /// Set the proof callback for PROVE_APP strategy
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&Packet) -> bool + Send + Sync + 'static,
    {
        self.callback = Some(Arc::new(callback));
        self
    }

    /// Determine if a proof should be sent for a packet
    pub fn should_prove(&self, packet: &Packet) -> bool {
        match self.strategy {
            ProofStrategy::None => false,
            ProofStrategy::All => true,
            ProofStrategy::App => {
                if let Some(ref callback) = self.callback {
                    callback(packet)
                } else {
                    false
                }
            }
        }
    }
}

impl std::fmt::Debug for ProofConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofConfig")
            .field("strategy", &self.strategy)
            .field("has_callback", &self.callback.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_strategy_default() {
        assert_eq!(ProofStrategy::default(), ProofStrategy::None);
    }

    #[test]
    fn test_proof_strategy_values_match_python() {
        // Python: PROVE_NONE = 0x21, PROVE_APP = 0x22, PROVE_ALL = 0x23
        assert_eq!(ProofStrategy::None as u8, 0x21);
        assert_eq!(ProofStrategy::App as u8, 0x22);
        assert_eq!(ProofStrategy::All as u8, 0x23);
    }

    #[test]
    fn test_proof_strategy_from_u8() {
        assert_eq!(ProofStrategy::from(0x21), ProofStrategy::None);
        assert_eq!(ProofStrategy::from(0x22), ProofStrategy::App);
        assert_eq!(ProofStrategy::from(0x23), ProofStrategy::All);
    }

    #[test]
    fn test_proof_strategy_invalid_defaults_to_none() {
        // Invalid values default to None (0x21)
        assert_eq!(ProofStrategy::from(0x00), ProofStrategy::None);
        assert_eq!(ProofStrategy::from(0x01), ProofStrategy::None);
        assert_eq!(ProofStrategy::from(0x20), ProofStrategy::None);
        assert_eq!(ProofStrategy::from(0x24), ProofStrategy::None);
        assert_eq!(ProofStrategy::from(0xFF), ProofStrategy::None);
    }

    #[test]
    fn test_proof_config() {
        let config = ProofConfig::new(ProofStrategy::All);
        // Can't easily test should_prove without a real packet, but we can verify strategy
        assert_eq!(config.strategy, ProofStrategy::All);
    }
}

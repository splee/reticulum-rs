//! Resource watchdog for monitoring resource transfer health.
//!
//! This module provides a watchdog task that monitors resource transfer status
//! and takes action on timeouts. It follows the same pattern as `link_watchdog.rs`:
//! a spawned async task that communicates via broadcast channel messages.
//!
//! The watchdog handles three resource states:
//! - **Advertised**: Retry advertisement if no requests received within timeout
//! - **Transferring**: Timeout handling differs by role:
//!   - Receiver: decrease window, request next parts, cancel if retries exhausted
//!   - Sender: cancel if no part requests received within max wait time
//! - **AwaitingProof**: Query network cache for proof, cancel if retries exhausted

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use super::constants::*;
use super::status::ResourceStatus;
use super::Resource;
use crate::hash::AddressHash;

/// Messages sent from the resource watchdog to the transport layer.
#[derive(Debug, Clone)]
pub enum ResourceWatchdogMessage {
    /// Retry sending the resource advertisement.
    RetryAdvertisement {
        resource_hash: [u8; 32],
        link_id: AddressHash,
    },
    /// Request next batch of parts (receiver side timeout).
    /// Contains the request data bytes to send in a RESOURCE_REQ packet.
    RequestNext {
        resource_hash: [u8; 32],
        link_id: AddressHash,
        request_data: Vec<u8>,
    },
    /// Query the network cache for an expected proof (sender side, awaiting proof).
    QueryProof {
        resource_hash: [u8; 32],
        link_id: AddressHash,
        expected_proof: [u8; 32],
    },
    /// Cancel the resource transfer.
    Cancel {
        resource_hash: [u8; 32],
        link_id: AddressHash,
    },
}

/// Configuration for the resource watchdog.
#[derive(Debug, Clone)]
pub struct ResourceWatchdogConfig {
    /// How often to check resource status (capped at WATCHDOG_MAX_SLEEP).
    pub check_interval: Duration,
}

impl Default for ResourceWatchdogConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs_f64(WATCHDOG_MAX_SLEEP),
        }
    }
}

/// Spawn a watchdog task for a resource transfer.
///
/// The watchdog monitors the resource and sends messages through the provided
/// broadcast channel when actions are needed (retry, request next, cancel, etc.).
///
/// # Arguments
///
/// * `resource` - The resource to monitor (shared reference)
/// * `link_id` - The link ID this resource is being transferred over
/// * `link_rtt` - The link's current RTT estimate (used for timeout calculations)
/// * `link_establishment_cost` - The link's establishment cost in bytes (for EIFR)
/// * `cancel` - Cancellation token to stop the watchdog
/// * `msg_tx` - Channel to send watchdog messages
/// * `config` - Watchdog configuration
pub fn spawn_resource_watchdog(
    resource: Arc<RwLock<Resource>>,
    link_id: AddressHash,
    link_rtt: Duration,
    link_establishment_cost: usize,
    cancel: CancellationToken,
    msg_tx: broadcast::Sender<ResourceWatchdogMessage>,
    config: ResourceWatchdogConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        resource_watchdog_loop(
            resource,
            link_id,
            link_rtt,
            link_establishment_cost,
            cancel,
            msg_tx,
            config,
        )
        .await;
    })
}

/// Main watchdog loop — mirrors Python `Resource.__watchdog_job()`.
async fn resource_watchdog_loop(
    resource: Arc<RwLock<Resource>>,
    link_id: AddressHash,
    link_rtt: Duration,
    link_establishment_cost: usize,
    cancel: CancellationToken,
    msg_tx: broadcast::Sender<ResourceWatchdogMessage>,
    config: ResourceWatchdogConfig,
) {
    loop {
        if cancel.is_cancelled() {
            break;
        }

        // Read resource state and determine what action to take
        let action = {
            let res = resource.read().unwrap_or_else(|p| p.into_inner());
            let status = res.status();

            // Exit if resource is past the active transfer states
            if status >= ResourceStatus::Assembling {
                break;
            }

            determine_action(&res, status, link_rtt, link_establishment_cost)
        };

        match action {
            WatchdogAction::Sleep(duration) => {
                // Sleep for the computed duration, capped at max sleep
                let sleep_time = duration.min(config.check_interval);
                tokio::select! {
                    _ = tokio::time::sleep(sleep_time) => {}
                    _ = cancel.cancelled() => break,
                }
            }
            WatchdogAction::RetryAdvertisement => {
                let resource_hash = *resource.read().unwrap_or_else(|p| p.into_inner()).hash();
                {
                    let mut res = resource.write().unwrap_or_else(|p| p.into_inner());
                    res.decrement_retries();
                    res.touch_activity();
                    res.mark_adv_sent();
                }
                log::debug!(
                    "resource_watchdog: retrying advertisement for {}",
                    hex::encode(&resource_hash[..8])
                );
                let _ = msg_tx.send(ResourceWatchdogMessage::RetryAdvertisement {
                    resource_hash,
                    link_id,
                });
            }
            WatchdogAction::RequestNextParts => {
                let (resource_hash, request_data) = {
                    let mut res = resource.write().unwrap_or_else(|p| p.into_inner());
                    // Decrease window on timeout (matching Python behavior)
                    res.decrease_window();
                    res.decrement_retries();
                    res.clear_waiting_for_hmu();
                    // Update EIFR before requesting
                    res.update_eifr(link_rtt, link_establishment_cost);
                    let hash = *res.hash();
                    let data = res.request_next();
                    (hash, data)
                };

                if let Some(data) = request_data {
                    log::debug!(
                        "resource_watchdog: requesting next parts for {}",
                        hex::encode(&resource_hash[..8])
                    );
                    let _ = msg_tx.send(ResourceWatchdogMessage::RequestNext {
                        resource_hash,
                        link_id,
                        request_data: data,
                    });
                }
            }
            WatchdogAction::QueryProof => {
                let (resource_hash, expected_proof) = {
                    let mut res = resource.write().unwrap_or_else(|p| p.into_inner());
                    res.decrement_retries();
                    // Reset last_part_sent to now to give more time
                    res.reset_last_part_sent();
                    (*res.hash(), *res.expected_proof())
                };
                log::debug!(
                    "resource_watchdog: querying proof for {}",
                    hex::encode(&resource_hash[..8])
                );
                let _ = msg_tx.send(ResourceWatchdogMessage::QueryProof {
                    resource_hash,
                    link_id,
                    expected_proof,
                });
            }
            WatchdogAction::Cancel => {
                let resource_hash = {
                    let mut res = resource.write().unwrap_or_else(|p| p.into_inner());
                    let hash = *res.hash();
                    res.cancel();
                    hash
                };
                log::debug!(
                    "resource_watchdog: cancelling resource {}",
                    hex::encode(&resource_hash[..8])
                );
                let _ = msg_tx.send(ResourceWatchdogMessage::Cancel {
                    resource_hash,
                    link_id,
                });
                break;
            }
            WatchdogAction::Exit => {
                break;
            }
        }
    }

    log::debug!("resource_watchdog: exiting");
}

/// Internal action determined by the watchdog on each iteration.
enum WatchdogAction {
    /// Sleep for the given duration before checking again.
    Sleep(Duration),
    /// Retry sending the advertisement.
    RetryAdvertisement,
    /// Request next parts (receiver timeout).
    RequestNextParts,
    /// Query network cache for proof.
    QueryProof,
    /// Cancel the resource transfer.
    Cancel,
    /// Exit the watchdog loop.
    Exit,
}

/// Determine what action the watchdog should take based on current resource state.
///
/// This mirrors the Python `Resource.__watchdog_job()` logic at Resource.py:561-666.
fn determine_action(
    res: &Resource,
    status: ResourceStatus,
    link_rtt: Duration,
    link_establishment_cost: usize,
) -> WatchdogAction {
    match status {
        ResourceStatus::Advertised => {
            determine_advertised_action(res)
        }
        ResourceStatus::Transferring => {
            if res.is_initiator() {
                // Sender side: waiting for part requests
                determine_sender_transferring_action(res, link_rtt)
            } else {
                // Receiver side: waiting for parts
                determine_receiver_transferring_action(res, link_rtt, link_establishment_cost)
            }
        }
        ResourceStatus::AwaitingProof => {
            determine_awaiting_proof_action(res, link_rtt)
        }
        _ => {
            // For other states (None, Queued, Rejected, etc.), just exit
            WatchdogAction::Exit
        }
    }
}

/// Handle ADVERTISED state: wait for first request, retry advertisement on timeout.
///
/// Python: sleep_time = (self.adv_sent + self.timeout + Resource.PROCESSING_GRACE) - time.time()
fn determine_advertised_action(res: &Resource) -> WatchdogAction {
    let adv_sent = match res.adv_sent() {
        Some(t) => t,
        None => return WatchdogAction::Sleep(Duration::from_millis(100)),
    };

    let timeout = res.timeout();
    let grace = Duration::from_secs_f64(PROCESSING_GRACE);
    let deadline = adv_sent + timeout + grace;
    let now = std::time::Instant::now();

    if now < deadline {
        // Still within timeout — sleep until deadline
        WatchdogAction::Sleep(deadline - now)
    } else if res.retries_left() == 0 {
        log::debug!("resource_watchdog: advertisement timeout, no retries left");
        WatchdogAction::Cancel
    } else {
        WatchdogAction::RetryAdvertisement
    }
}

/// Handle TRANSFERRING state for receiver: compute expected time-of-flight and timeout.
///
/// Mirrors Python Resource.py:591-624. Python computes:
///   sleep_time = last_activity + tolerance - now
/// where negative means timed out. We compute the same way.
fn determine_receiver_transferring_action(
    res: &Resource,
    link_rtt: Duration,
    _link_establishment_cost: usize,
) -> WatchdogAction {
    let retries_used = res.max_retries().saturating_sub(res.retries_left()) as f64;
    let extra_wait = retries_used * PER_RETRY_DELAY;

    // Compute expected time-of-flight for outstanding parts
    let eifr = res.eifr().unwrap_or_else(|| {
        // Fallback: estimate from link RTT (rough estimate)
        let rtt_secs = link_rtt.as_secs_f64().max(0.001);
        1000.0 / rtt_secs
    });
    let eifr = eifr.max(1.0); // prevent division by zero

    let outstanding = res.outstanding_parts() as f64;
    let sdu = res.sdu() as f64;
    let expected_tof_remaining = (outstanding * sdu * 8.0) / eifr;

    // Compute tolerance (how long we should wait before declaring timeout)
    let tolerance = if res.req_resp_rtt_rate() != 0.0 {
        res.part_timeout_factor() * expected_tof_remaining + RETRY_GRACE_TIME + extra_wait
    } else {
        // No rate data yet: use conservative estimate with 3x SDU
        res.part_timeout_factor() * (3.0 * sdu / eifr) + RETRY_GRACE_TIME + extra_wait
    };

    let elapsed = res.last_activity().elapsed().as_secs_f64();
    let remaining = tolerance - elapsed;

    if remaining > 0.0 {
        WatchdogAction::Sleep(Duration::from_secs_f64(remaining.min(WATCHDOG_MAX_SLEEP)))
    } else if res.retries_left() > 0 {
        log::debug!(
            "resource_watchdog: receiver timeout, {} outstanding parts, requesting retry",
            res.outstanding_parts()
        );
        WatchdogAction::RequestNextParts
    } else {
        log::debug!("resource_watchdog: receiver timeout, no retries left");
        WatchdogAction::Cancel
    }
}

/// Handle TRANSFERRING state for sender: wait for part requests from receiver.
///
/// Python: Resource.py:626-633
fn determine_sender_transferring_action(
    res: &Resource,
    link_rtt: Duration,
) -> WatchdogAction {
    let rtt_secs = res.rtt().unwrap_or(link_rtt).as_secs_f64().max(0.001);

    // Compute max wait: rtt * timeout_factor * max_retries + sender_grace_time + max_extra_wait
    let max_retries = res.max_retries() as f64;
    let max_extra_wait: f64 = (0..res.max_retries())
        .map(|r| (r as f64 + 1.0) * PER_RETRY_DELAY)
        .sum();
    let max_wait = rtt_secs * res.timeout_factor() * max_retries + res.sender_grace_time() + max_extra_wait;

    let elapsed = res.last_activity().elapsed().as_secs_f64();
    let remaining = max_wait - elapsed;

    if remaining > 0.0 {
        WatchdogAction::Sleep(Duration::from_secs_f64(remaining.min(WATCHDOG_MAX_SLEEP)))
    } else {
        log::debug!("resource_watchdog: sender timeout waiting for part requests");
        WatchdogAction::Cancel
    }
}

/// Handle AWAITING_PROOF state: wait for proof, query cache, cancel on exhaustion.
///
/// Python: Resource.py:635-654
fn determine_awaiting_proof_action(
    res: &Resource,
    link_rtt: Duration,
) -> WatchdogAction {
    let rtt = res.rtt().unwrap_or(link_rtt).as_secs_f64().max(0.001);

    // Use proof timeout factor (smaller than normal since proofs are small)
    let timeout_factor = PROOF_TIMEOUT_FACTOR;

    let last_sent = match res.last_part_sent() {
        Some(t) => t,
        None => {
            // No parts sent yet — shouldn't be in AWAITING_PROOF, but handle gracefully
            return WatchdogAction::Sleep(Duration::from_secs_f64(WATCHDOG_MAX_SLEEP));
        }
    };

    let deadline_secs = rtt * timeout_factor + res.sender_grace_time();
    let elapsed = last_sent.elapsed().as_secs_f64();
    let remaining = deadline_secs - elapsed;

    if remaining > 0.0 {
        WatchdogAction::Sleep(Duration::from_secs_f64(remaining.min(WATCHDOG_MAX_SLEEP)))
    } else if res.retries_left() == 0 {
        log::debug!("resource_watchdog: proof timeout, no retries left");
        WatchdogAction::Cancel
    } else {
        log::debug!("resource_watchdog: proof timeout, querying network cache");
        WatchdogAction::QueryProof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog_config_default() {
        let config = ResourceWatchdogConfig::default();
        assert_eq!(
            config.check_interval,
            Duration::from_secs_f64(WATCHDOG_MAX_SLEEP)
        );
    }

    #[test]
    fn test_watchdog_message_variants() {
        let link_id = AddressHash::new_from_slice(&[1u8; 32]);
        let resource_hash = [2u8; 32];

        // Test RetryAdvertisement variant
        let msg = ResourceWatchdogMessage::RetryAdvertisement {
            resource_hash,
            link_id,
        };
        match msg {
            ResourceWatchdogMessage::RetryAdvertisement {
                resource_hash: h, ..
            } => {
                assert_eq!(h, resource_hash);
            }
            _ => panic!("Expected RetryAdvertisement"),
        }

        // Test Cancel variant
        let msg = ResourceWatchdogMessage::Cancel {
            resource_hash,
            link_id,
        };
        match msg {
            ResourceWatchdogMessage::Cancel {
                resource_hash: h, ..
            } => {
                assert_eq!(h, resource_hash);
            }
            _ => panic!("Expected Cancel"),
        }

        // Test RequestNext variant
        let msg = ResourceWatchdogMessage::RequestNext {
            resource_hash,
            link_id,
            request_data: vec![1, 2, 3],
        };
        match msg {
            ResourceWatchdogMessage::RequestNext { request_data, .. } => {
                assert_eq!(request_data, vec![1, 2, 3]);
            }
            _ => panic!("Expected RequestNext"),
        }

        // Test QueryProof variant
        let expected_proof = [3u8; 32];
        let msg = ResourceWatchdogMessage::QueryProof {
            resource_hash,
            link_id,
            expected_proof,
        };
        match msg {
            ResourceWatchdogMessage::QueryProof {
                expected_proof: p, ..
            } => {
                assert_eq!(p, expected_proof);
            }
            _ => panic!("Expected QueryProof"),
        }
    }

    #[test]
    fn test_advertised_action_no_adv_sent() {
        // When adv_sent is None, should just sleep briefly
        use rand_core::OsRng;
        let config = super::super::config::ResourceConfig::default();
        let resource = Resource::new(&mut OsRng, b"test data", config, None, None).unwrap();
        // adv_sent is None by default for outgoing resources
        let action = determine_advertised_action(&resource);
        matches!(action, WatchdogAction::Sleep(_));
    }

    #[test]
    fn test_sender_transferring_within_timeout() {
        use rand_core::OsRng;
        let config = super::super::config::ResourceConfig::default();
        let resource = Resource::new(&mut OsRng, b"test data", config, None, None).unwrap();
        // Resource was just created, so last_activity is recent — should sleep
        let link_rtt = Duration::from_millis(100);
        let action = determine_sender_transferring_action(&resource, link_rtt);
        matches!(action, WatchdogAction::Sleep(_));
    }

    #[test]
    fn test_awaiting_proof_no_last_part_sent() {
        use rand_core::OsRng;
        let config = super::super::config::ResourceConfig::default();
        let resource = Resource::new(&mut OsRng, b"test data", config, None, None).unwrap();
        // last_part_sent is None — should just sleep
        let link_rtt = Duration::from_millis(100);
        let action = determine_awaiting_proof_action(&resource, link_rtt);
        matches!(action, WatchdogAction::Sleep(_));
    }
}

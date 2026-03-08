//! Progress tracking and display for file transfers.
//!
//! This module provides the `TransferProgress` struct for tracking and
//! displaying file transfer progress with a spinner animation.

use std::io::Write;
use std::time::Instant;

use reticulum::cli::format::{size_str, SPINNER_CHARS};

/// Progress tracker for file transfers.
///
/// Tracks transfer progress and displays a spinner animation with
/// transfer statistics (progress percentage, transferred/total size, speed).
pub struct TransferProgress {
    total_size: usize,
    transfer_size: usize,
    transferred: usize,
    start_time: Instant,
    spinner_idx: usize,
    silent: bool,
    show_phy_rates: bool,
}

impl TransferProgress {
    /// Create a new progress tracker.
    ///
    /// # Arguments
    /// * `total_size` - Total logical (uncompressed) size in bytes
    /// * `transfer_size` - Wire-level transfer size in bytes (after compression/encryption)
    /// * `silent` - If true, suppress all progress output
    /// * `show_phy_rates` - If true, display physical layer transfer rates
    pub fn new(total_size: usize, transfer_size: usize, silent: bool, show_phy_rates: bool) -> Self {
        Self {
            total_size,
            transfer_size,
            transferred: 0,
            start_time: Instant::now(),
            spinner_idx: 0,
            silent,
            show_phy_rates,
        }
    }

    /// Update the progress with additional transferred bytes.
    pub fn update(&mut self, bytes: usize) {
        self.transferred += bytes;
        self.spinner_idx = (self.spinner_idx + 1) % SPINNER_CHARS.len();
    }

    /// Display the current progress on stdout.
    ///
    /// Shows a spinner, progress percentage, transferred/total size, and speed.
    /// Uses carriage return to overwrite the line for animation effect.
    pub fn display(&self) {
        if self.silent {
            return;
        }

        let progress = if self.total_size > 0 {
            (self.transferred as f64 / self.total_size as f64) * 100.0
        } else {
            0.0
        };

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            self.transferred as f64 / elapsed
        } else {
            0.0
        };

        let spinner = SPINNER_CHARS[self.spinner_idx];

        // Compute physical layer rate string if enabled.
        // Physical speed is derived from data speed scaled by the ratio of
        // wire-level transfer size to logical data size.
        let phy_str = if self.show_phy_rates && self.total_size > 0 {
            let phy_speed = speed * (self.transfer_size as f64 / self.total_size as f64);
            let pss = size_str(phy_speed as u64, 'b');
            format!(" ({}ps at physical layer)", pss)
        } else {
            String::new()
        };

        // Use carriage return to overwrite line
        print!(
            "\r{} {:.1}%  {} / {}  {}/s{}   ",
            spinner,
            progress,
            size_str(self.transferred as u64, 'B'),
            size_str(self.total_size as u64, 'B'),
            size_str(speed as u64, 'B'),
            phy_str,
        );
        std::io::stdout().flush().ok();
    }

    /// Display the final transfer result.
    ///
    /// Shows either a success message with statistics or a failure message.
    pub fn finish(&self, success: bool) {
        if self.silent {
            return;
        }

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            self.transferred as f64 / elapsed
        } else {
            0.0
        };

        if success {
            // Compute physical layer rate string for final output
            let phy_str = if self.show_phy_rates && self.total_size > 0 {
                let phy_speed = speed * (self.transfer_size as f64 / self.total_size as f64);
                let pss = size_str(phy_speed as u64, 'b');
                format!(" ({}ps at physical layer)", pss)
            } else {
                String::new()
            };

            println!(
                "\r✓ 100%  {} transferred in {:.1}s ({}/s{})   ",
                size_str(self.transferred as u64, 'B'),
                elapsed,
                size_str(speed as u64, 'B'),
                phy_str,
            );
        } else {
            println!("\r✗ Transfer failed                         ");
        }
    }
}

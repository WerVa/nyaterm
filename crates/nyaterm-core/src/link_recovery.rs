//! Policy for recovering a session after its connection drops.
//!
//! Pure state: no timers, no I/O, no UI. The caller owns the clock and the
//! reconnect itself and drives this machine with events, which keeps the rules
//! (which endings are worth recovering, how long to wait, when to give up)
//! testable without a network.

use std::time::{Duration, Instant};

/// Exit reasons the SSH transport reports. They live here, next to the
/// classifier, so the producer and the policy cannot drift apart.
pub const SSH_REASON_CONNECTION_TASK_ENDED: &str = "SSH connection task ended";
pub const SSH_REASON_CONNECTION_CLOSED: &str = "SSH connection closed";

/// Why a session ended, as far as the transport can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEndCause {
    /// The remote shell exited or the user closed it. Reconnecting would undo
    /// what they asked for, so it must never be automatic.
    Finished,
    /// The connection died underneath a live session: keepalive timeout, reset,
    /// or the network changed.
    LinkLost,
}

/// Classifies a transport exit reason.
///
/// Anything unrecognised counts as `Finished`: a missed recovery only costs the
/// user one keypress, while a wrong automatic reconnect can loop against a
/// server that keeps closing the session.
pub fn classify_ssh_end(reason: &str) -> SessionEndCause {
    match reason {
        SSH_REASON_CONNECTION_TASK_ENDED | SSH_REASON_CONNECTION_CLOSED => {
            SessionEndCause::LinkLost
        }
        _ => SessionEndCause::Finished,
    }
}

/// Whether a failed reconnect attempt is worth repeating.
///
/// Only failures that look like the network, not like a decision by the server
/// or the user. Retrying a rejected credential on a timer can lock the account
/// or trip fail2ban, and retrying a host-key mismatch would defeat the check, so
/// those stop the recovery. Anything unrecognised also stops it: the user is
/// one keypress from retrying by hand.
pub fn is_retryable_connect_error(error: &str) -> bool {
    const STOP: &[&str] = &[
        "auth",
        "permission denied",
        "password",
        "passphrase",
        "denied",
        "rejected",
        "host key",
        "hostkey",
        "known_hosts",
        "fingerprint",
        "cancel",
        "no supported",
        "invalid",
    ];
    const NETWORK: &[&str] = &[
        "timed out",
        "timeout",
        "refused",
        "unreachable",
        "no route",
        "reset",
        "broken pipe",
        "lookup",
        "resolve",
        "dns",
        "network",
        "connection closed",
        "connection aborted",
        "unexpected eof",
        "disconnected",
        "temporarily",
    ];
    let error = error.to_ascii_lowercase();
    if STOP.iter().any(|marker| error.contains(marker)) {
        return false;
    }
    NETWORK.iter().any(|marker| error.contains(marker))
}

/// Number of unanswered keepalives to tolerate so that a silent link survives
/// for at least `grace` before the SSH library drops it.
///
/// This is the only point at which the *same* connection can come back after a
/// network blip: once the library gives up, the TCP session is gone and a new
/// one has to be negotiated. Never lowers the library default of three.
pub fn keepalive_max_for_grace(interval: Duration, grace: Duration) -> usize {
    const DEFAULT: usize = 3;
    const CEILING: usize = 100;
    if interval.is_zero() {
        return DEFAULT;
    }
    let needed = grace.as_secs_f64() / interval.as_secs_f64();
    (needed.ceil() as usize).clamp(DEFAULT, CEILING)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicy {
    /// Waits before attempts 1, 2, ...; the last entry repeats.
    pub delays: Vec<Duration>,
    pub max_attempts: u32,
    /// Counted from the moment the link was lost.
    pub max_elapsed: Duration,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            delays: [1, 2, 4, 8, 15, 30]
                .into_iter()
                .map(Duration::from_secs)
                .collect(),
            max_attempts: 12,
            max_elapsed: Duration::from_secs(10 * 60),
        }
    }
}

impl RecoveryPolicy {
    fn delay_for(&self, attempt: u32) -> Duration {
        let index = (attempt.saturating_sub(1)) as usize;
        self.delays
            .get(index)
            .or_else(|| self.delays.last())
            .copied()
            .unwrap_or(Duration::from_secs(5))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GiveUpReason {
    AttemptsExhausted,
    TimeExhausted,
}

/// What the caller should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStep {
    /// Wait `after`, then start attempt number `attempt` (1-based).
    Retry {
        attempt: u32,
        after: Duration,
    },
    GiveUp(GiveUpReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    /// A retry is scheduled but has not started.
    Waiting,
    /// An attempt is running.
    Connecting,
}

#[derive(Debug, Clone)]
pub struct LinkRecovery {
    policy: RecoveryPolicy,
    phase: Phase,
    lost_at: Option<Instant>,
    attempt: u32,
}

impl LinkRecovery {
    pub fn new(policy: RecoveryPolicy) -> Self {
        Self {
            policy,
            phase: Phase::Idle,
            lost_at: None,
            attempt: 0,
        }
    }

    pub fn is_active(&self) -> bool {
        self.phase != Phase::Idle
    }

    /// Whether a retry is scheduled and has not started; used to ignore a timer
    /// that fires after the episode moved on.
    pub fn is_waiting_for(&self, attempt: u32) -> bool {
        self.phase == Phase::Waiting && self.attempt == attempt
    }

    /// Attempts started or scheduled so far in this episode.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The link dropped. Starts an episode and returns the first step. Returns
    /// `None` when an episode is already running, so a duplicate exit event
    /// cannot restart the backoff or stack a second reconnect.
    pub fn link_lost(&mut self, now: Instant) -> Option<RecoveryStep> {
        if self.phase != Phase::Idle {
            return None;
        }
        self.lost_at = Some(now);
        self.attempt = 0;
        Some(self.schedule_next(now))
    }

    /// The scheduled retry fired and a reconnect is now in flight.
    pub fn attempt_started(&mut self) {
        if self.phase == Phase::Waiting {
            self.phase = Phase::Connecting;
        }
    }

    /// The running attempt failed.
    pub fn attempt_failed(&mut self, now: Instant) -> RecoveryStep {
        if self.phase == Phase::Idle {
            return RecoveryStep::GiveUp(GiveUpReason::AttemptsExhausted);
        }
        self.schedule_next(now)
    }

    pub fn succeeded(&mut self) {
        self.reset();
    }

    /// The user took over (typed, reconnected by hand, closed the tab).
    pub fn cancel(&mut self) {
        self.reset();
    }

    fn reset(&mut self) {
        self.phase = Phase::Idle;
        self.lost_at = None;
        self.attempt = 0;
    }

    fn schedule_next(&mut self, now: Instant) -> RecoveryStep {
        let lost_at = self.lost_at.unwrap_or(now);
        let next_attempt = self.attempt.saturating_add(1);
        if next_attempt > self.policy.max_attempts {
            self.reset();
            return RecoveryStep::GiveUp(GiveUpReason::AttemptsExhausted);
        }
        let after = self.policy.delay_for(next_attempt);
        let elapsed = now.saturating_duration_since(lost_at);
        if elapsed.saturating_add(after) > self.policy.max_elapsed {
            self.reset();
            return RecoveryStep::GiveUp(GiveUpReason::TimeExhausted);
        }
        self.attempt = next_attempt;
        self.phase = Phase::Waiting;
        RecoveryStep::Retry {
            attempt: self.attempt,
            after,
        }
    }
}

#[cfg(test)]
mod tests;

//! Per-session automatic reconnect episodes.
//!
//! Owns only the bookkeeping; the policy lives in `nyaterm_core::link_recovery`
//! and the timers and the reconnect itself in `link_recovery_runtime`. Keyed by
//! the id of the session that was lost: a successful reconnect creates a new
//! session id, so the old key retires with the episode.

use std::collections::HashMap;
use std::time::Instant;

use nyaterm_core::link_recovery::{LinkRecovery, RecoveryPolicy, RecoveryStep};

#[derive(Default)]
pub(in crate::features) struct LinkRecoveryRegistry {
    episodes: HashMap<String, LinkRecovery>,
}

impl LinkRecoveryRegistry {
    /// Starts an episode. `None` when one is already running for this session.
    pub(in crate::features) fn begin(
        &mut self,
        session_id: &str,
        now: Instant,
    ) -> Option<RecoveryStep> {
        let episode = self
            .episodes
            .entry(session_id.to_string())
            .or_insert_with(|| LinkRecovery::new(RecoveryPolicy::default()));
        let step = episode.link_lost(now);
        if step.is_none() || matches!(step, Some(RecoveryStep::GiveUp(_))) {
            self.prune(session_id);
        }
        step
    }

    pub(in crate::features) fn is_active(&self, session_id: &str) -> bool {
        self.episodes
            .get(session_id)
            .is_some_and(LinkRecovery::is_active)
    }

    pub(in crate::features) fn is_waiting_for(&self, session_id: &str, attempt: u32) -> bool {
        self.episodes
            .get(session_id)
            .is_some_and(|episode| episode.is_waiting_for(attempt))
    }

    pub(in crate::features) fn attempt_started(&mut self, session_id: &str) {
        if let Some(episode) = self.episodes.get_mut(session_id) {
            episode.attempt_started();
        }
    }

    /// The running attempt failed. `None` when no episode is running, for
    /// example because the user already took over.
    pub(in crate::features) fn attempt_failed(
        &mut self,
        session_id: &str,
        now: Instant,
    ) -> Option<RecoveryStep> {
        let episode = self.episodes.get_mut(session_id)?;
        if !episode.is_active() {
            self.prune(session_id);
            return None;
        }
        let step = episode.attempt_failed(now);
        if matches!(step, RecoveryStep::GiveUp(_)) {
            self.prune(session_id);
        }
        Some(step)
    }

    /// Ends the episode, whether it succeeded or the user took over.
    pub(in crate::features) fn finish(&mut self, session_id: &str) {
        self.episodes.remove(session_id);
    }

    fn prune(&mut self, session_id: &str) {
        if self
            .episodes
            .get(session_id)
            .is_some_and(|episode| !episode.is_active())
        {
            self.episodes.remove(session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use nyaterm_core::link_recovery::{GiveUpReason, RecoveryStep};

    use super::LinkRecoveryRegistry;

    #[test]
    fn an_episode_is_tracked_per_session() {
        let now = Instant::now();
        let mut registry = LinkRecoveryRegistry::default();

        assert!(matches!(
            registry.begin("a", now),
            Some(RecoveryStep::Retry { attempt: 1, .. })
        ));
        assert!(registry.is_active("a"));
        assert!(!registry.is_active("b"));
        assert!(registry.begin("a", now).is_none(), "duplicate loss ignored");
        assert!(registry.begin("b", now).is_some());
    }

    #[test]
    fn a_timer_for_a_superseded_attempt_is_not_waiting() {
        let now = Instant::now();
        let mut registry = LinkRecoveryRegistry::default();
        registry.begin("a", now);
        assert!(registry.is_waiting_for("a", 1));

        registry.attempt_started("a");
        assert!(!registry.is_waiting_for("a", 1));
        registry.attempt_failed("a", now);
        assert!(registry.is_waiting_for("a", 2));
        assert!(
            !registry.is_waiting_for("a", 1),
            "attempt 1's timer is stale"
        );
    }

    #[test]
    fn finishing_ends_the_episode_and_late_failures_are_ignored() {
        let now = Instant::now();
        let mut registry = LinkRecoveryRegistry::default();
        registry.begin("a", now);
        registry.attempt_started("a");

        registry.finish("a");

        assert!(!registry.is_active("a"));
        assert_eq!(registry.attempt_failed("a", now), None);
        assert!(matches!(
            registry.begin("a", now),
            Some(RecoveryStep::Retry { attempt: 1, .. })
        ));
    }

    #[test]
    fn exhausting_the_budget_clears_the_episode() {
        let now = Instant::now();
        let mut registry = LinkRecoveryRegistry::default();
        registry.begin("a", now);
        registry.attempt_started("a");

        let step = registry.attempt_failed("a", now + Duration::from_secs(11 * 60));

        assert_eq!(
            step,
            Some(RecoveryStep::GiveUp(GiveUpReason::TimeExhausted))
        );
        assert!(!registry.is_active("a"));
    }
}

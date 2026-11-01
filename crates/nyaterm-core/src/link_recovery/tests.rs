use std::time::{Duration, Instant};

use super::{
    GiveUpReason, LinkRecovery, RecoveryPolicy, RecoveryStep, SSH_REASON_CONNECTION_CLOSED,
    SSH_REASON_CONNECTION_TASK_ENDED, SessionEndCause, classify_ssh_end,
    is_retryable_connect_error, keepalive_max_for_grace,
};

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

fn retry(attempt: u32, after: u64) -> Option<RecoveryStep> {
    Some(RecoveryStep::Retry {
        attempt,
        after: secs(after),
    })
}

#[test]
fn lost_connections_are_recoverable_and_finished_shells_are_not() {
    assert_eq!(
        classify_ssh_end(SSH_REASON_CONNECTION_TASK_ENDED),
        SessionEndCause::LinkLost
    );
    assert_eq!(
        classify_ssh_end(SSH_REASON_CONNECTION_CLOSED),
        SessionEndCause::LinkLost
    );
    for reason in [
        "SSH channel exit status 0",
        "SSH channel exit status 130",
        "SSH channel EOF",
        "SSH channel closed by remote",
        "",
        "something new the transport starts saying",
    ] {
        assert_eq!(
            classify_ssh_end(reason),
            SessionEndCause::Finished,
            "{reason}"
        );
    }
}

#[test]
fn grace_period_raises_keepalive_tolerance_but_never_lowers_it() {
    assert_eq!(keepalive_max_for_grace(secs(30), secs(30)), 3);
    assert_eq!(keepalive_max_for_grace(secs(10), secs(30)), 3);
    assert_eq!(keepalive_max_for_grace(secs(5), secs(30)), 6);
    assert_eq!(keepalive_max_for_grace(secs(7), secs(30)), 5);
    assert_eq!(keepalive_max_for_grace(secs(1), secs(30)), 30);
    assert_eq!(keepalive_max_for_grace(secs(60), secs(30)), 3);
    assert_eq!(keepalive_max_for_grace(secs(0), secs(30)), 3);
    assert_eq!(
        keepalive_max_for_grace(Duration::from_millis(1), secs(3600)),
        100
    );
}

#[test]
fn delays_back_off_and_the_last_one_repeats() {
    let start = Instant::now();
    let mut recovery = LinkRecovery::new(RecoveryPolicy::default());

    assert_eq!(recovery.link_lost(start), retry(1, 1));
    let mut seen = Vec::new();
    for _ in 0..6 {
        recovery.attempt_started();
        match recovery.attempt_failed(start) {
            RecoveryStep::Retry { after, .. } => seen.push(after.as_secs()),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(seen, [2, 4, 8, 15, 30, 30]);
}

#[test]
fn success_ends_the_episode_and_the_next_loss_starts_fresh() {
    let start = Instant::now();
    let mut recovery = LinkRecovery::new(RecoveryPolicy::default());
    recovery.link_lost(start);
    recovery.attempt_started();
    recovery.attempt_failed(start);
    assert_eq!(recovery.attempt(), 2);

    recovery.succeeded();

    assert!(!recovery.is_active());
    assert_eq!(recovery.link_lost(start), retry(1, 1));
}

#[test]
fn a_duplicate_loss_event_during_an_episode_is_ignored() {
    let start = Instant::now();
    let mut recovery = LinkRecovery::new(RecoveryPolicy::default());
    recovery.link_lost(start);
    recovery.attempt_started();

    assert_eq!(recovery.link_lost(start), None);
    assert_eq!(recovery.attempt(), 1, "backoff must not restart");
    assert!(recovery.is_active());
}

#[test]
fn gives_up_after_the_configured_number_of_attempts() {
    let policy = RecoveryPolicy {
        max_attempts: 3,
        ..RecoveryPolicy::default()
    };
    let start = Instant::now();
    let mut recovery = LinkRecovery::new(policy);
    recovery.link_lost(start);
    recovery.attempt_started();
    recovery.attempt_failed(start);
    recovery.attempt_started();
    recovery.attempt_failed(start);
    recovery.attempt_started();

    assert_eq!(
        recovery.attempt_failed(start),
        RecoveryStep::GiveUp(GiveUpReason::AttemptsExhausted)
    );
    assert!(!recovery.is_active());
}

#[test]
fn gives_up_when_the_next_wait_would_pass_the_time_budget() {
    let policy = RecoveryPolicy {
        max_elapsed: secs(60),
        ..RecoveryPolicy::default()
    };
    let start = Instant::now();
    let mut recovery = LinkRecovery::new(policy);
    recovery.link_lost(start);
    recovery.attempt_started();

    // 50 s in, the next wait is 2 s: still inside the budget.
    assert!(matches!(
        recovery.attempt_failed(start + secs(50)),
        RecoveryStep::Retry { .. }
    ));
    recovery.attempt_started();
    // 59 s in, the next wait is 4 s: it would end at 63 s.
    assert_eq!(
        recovery.attempt_failed(start + secs(59)),
        RecoveryStep::GiveUp(GiveUpReason::TimeExhausted)
    );
}

#[test]
fn cancel_stops_recovery_so_a_late_failure_cannot_revive_it() {
    let start = Instant::now();
    let mut recovery = LinkRecovery::new(RecoveryPolicy::default());
    recovery.link_lost(start);
    recovery.attempt_started();

    recovery.cancel();

    assert!(!recovery.is_active());
    assert_eq!(
        recovery.attempt_failed(start),
        RecoveryStep::GiveUp(GiveUpReason::AttemptsExhausted)
    );
}

#[test]
fn an_empty_delay_list_still_yields_a_finite_wait() {
    let policy = RecoveryPolicy {
        delays: Vec::new(),
        ..RecoveryPolicy::default()
    };
    let mut recovery = LinkRecovery::new(policy);

    assert_eq!(recovery.link_lost(Instant::now()), retry(1, 5));
}

#[test]
fn network_failures_are_retried_and_credential_failures_are_not() {
    for error in [
        "connection timed out",
        "Connection refused (os error 111)",
        "Network is unreachable",
        "No route to host",
        "failed to lookup address information",
        "Connection reset by peer",
        "unexpected EOF during handshake",
    ] {
        assert!(is_retryable_connect_error(error), "{error}");
    }
    for error in [
        "Authentication failed",
        "Permission denied (publickey,password)",
        "incorrect password",
        "wrong passphrase for key",
        "Host key verification failed: connection aborted",
        "server fingerprint changed",
        "connection attempt cancelled",
        "key rejected by server",
        "",
        "something unrecognised",
    ] {
        assert!(!is_retryable_connect_error(error), "{error}");
    }
}

#[test]
fn only_the_scheduled_attempt_is_waiting() {
    let start = Instant::now();
    let mut recovery = LinkRecovery::new(RecoveryPolicy::default());
    recovery.link_lost(start);
    assert!(recovery.is_waiting_for(1));
    assert!(!recovery.is_waiting_for(2));

    recovery.attempt_started();
    assert!(
        !recovery.is_waiting_for(1),
        "a started attempt is no longer waiting"
    );
}

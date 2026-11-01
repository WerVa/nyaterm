//! Automatic reconnect of SSH sessions whose connection was lost.
//!
//! The rules (which endings qualify, how long to wait, when to stop) are in
//! `nyaterm_core::link_recovery`; the bookkeeping is `LinkRecoveryRegistry`. This
//! file only connects them to the session events, a timer, and the ordinary
//! reconnect that the user's own "reconnect" already goes through, so state
//! migration, directory restore and tunnel restart behave identically.

use std::time::{Duration, Instant};

use gpui::Context;
use nyaterm_core::link_recovery::{
    GiveUpReason, RecoveryPolicy, RecoveryStep, SessionEndCause, classify_ssh_end,
    is_retryable_connect_error,
};

use crate::features::NyaTermApp;
use crate::models::SessionLaunchConfig;

impl NyaTermApp {
    /// Called for a session exit after the ordinary disconnect handling. Starts
    /// automatic recovery only for a lost link on an SSH session the user did not
    /// disconnect themselves.
    pub(in crate::features) fn maybe_begin_link_recovery(
        &mut self,
        session_id: &str,
        reason: &str,
        already_disconnected: bool,
        cx: &mut Context<Self>,
    ) {
        if already_disconnected
            || !self.settings.summary().terminal_auto_reconnect
            || classify_ssh_end(reason) != SessionEndCause::LinkLost
            || !self.session.metadata(session_id).is_some_and(|metadata| {
                matches!(metadata.launch_config, SessionLaunchConfig::Ssh(_))
            })
            || self.session.session_is_busy(session_id)
            || self.session.start_reconnect_is_pending(session_id)
        {
            return;
        }
        let Some(step) = self
            .session
            .link_recovery_mut()
            .begin(session_id, Instant::now())
        else {
            return;
        };
        self.apply_link_recovery_step(session_id.to_string(), step, cx);
    }

    /// The reconnect started by a retry failed to establish a session.
    pub(in crate::features) fn link_recovery_attempt_failed(
        &mut self,
        session_id: &str,
        error: &str,
        cx: &mut Context<Self>,
    ) {
        if !self.session.link_recovery().is_active(session_id) {
            return;
        }
        if !is_retryable_connect_error(error) {
            // A rejected credential or changed host key needs the user, and
            // repeating it on a timer could lock the account.
            self.session.link_recovery_mut().finish(session_id);
            self.report_link_recovery(
                session_id,
                &format!("Automatic reconnect stopped: {error}. Press Enter to reconnect."),
            );
            cx.notify();
            return;
        }
        let Some(step) = self
            .session
            .link_recovery_mut()
            .attempt_failed(session_id, Instant::now())
        else {
            return;
        };
        self.apply_link_recovery_step(session_id.to_string(), step, cx);
    }

    fn apply_link_recovery_step(
        &mut self,
        session_id: String,
        step: RecoveryStep,
        cx: &mut Context<Self>,
    ) {
        match step {
            RecoveryStep::Retry { attempt, after } => {
                let max = RecoveryPolicy::default().max_attempts;
                self.report_link_recovery(
                    &session_id,
                    &format!(
                        "Connection lost. Reconnecting in {}s (attempt {attempt}/{max}). \
                         Press Enter to reconnect now.",
                        after.as_secs().max(1)
                    ),
                );
                self.schedule_link_recovery_attempt(session_id, attempt, after, cx);
            }
            RecoveryStep::GiveUp(reason) => {
                let why = match reason {
                    GiveUpReason::AttemptsExhausted => "too many attempts",
                    GiveUpReason::TimeExhausted => "no connection for too long",
                };
                self.report_link_recovery(
                    &session_id,
                    &format!("Automatic reconnect stopped ({why}). Press Enter to reconnect."),
                );
            }
        }
        cx.notify();
    }

    /// Writes the notice into the tab and the status line.
    fn report_link_recovery(&mut self, session_id: &str, message: &str) {
        self.terminal.append_existing_session_text(
            session_id,
            &format!("\r\n\x1b[36m[{message}]\x1b[0m\r\n"),
        );
        self.shell.set_status(message.to_string());
    }

    fn schedule_link_recovery_attempt(
        &mut self,
        session_id: String,
        attempt: u32,
        after: Duration,
        cx: &mut Context<Self>,
    ) {
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(after).await;
            let _ = this.update(cx, |this, cx| {
                this.run_link_recovery_attempt(session_id, attempt, cx);
            });
        })
        .detach();
    }

    fn run_link_recovery_attempt(
        &mut self,
        session_id: String,
        attempt: u32,
        cx: &mut Context<Self>,
    ) {
        // A timer outlives the episode it was set for (the user reconnected by
        // hand, the tab closed); only the attempt currently waited for may run.
        if !self
            .session
            .link_recovery()
            .is_waiting_for(&session_id, attempt)
        {
            return;
        }
        if !self.settings.summary().terminal_auto_reconnect
            || !self.session.has_session(&session_id)
            || !self.session.is_disconnected(&session_id)
            || self.session.session_is_busy(&session_id)
            || self.session.start_reconnect_is_pending(&session_id)
        {
            self.session.link_recovery_mut().finish(&session_id);
            return;
        }
        self.session
            .link_recovery_mut()
            .attempt_started(&session_id);
        self.reconnect_session_with(session_id, None, true, cx);
    }
}

#[cfg(test)]
mod tests {
    use gpui::TestAppContext;
    use nyaterm_transport::SshSessionConfig;

    use crate::features::test_support::{
        app_with_visible_local_session, session_focus_test_window,
    };
    use crate::models::SessionLaunchConfig;
    use crate::test_support::TestConfigDir;

    const LOST: &str = "SSH connection task ended";

    /// A session whose launch config is SSH to a port that fails locally, so a
    /// reconnect starts for real without any network I/O.
    fn make_ssh(app: &mut crate::features::NyaTermApp) {
        let mut metadata = app.session.metadata("source").unwrap().clone();
        metadata.launch_config = SessionLaunchConfig::Ssh(Box::new(SshSessionConfig {
            host: "127.0.0.1".into(),
            port: 0,
            ..SshSessionConfig::default()
        }));
        app.session.register_session_metadata("source", metadata);
    }

    #[test]
    fn only_a_lost_ssh_link_starts_recovery() {
        let root = TestConfigDir::new("nyaterm-link-recovery-start");
        let mut cx = TestAppContext::single();
        let _cleanup = crate::test_support::TestAppCleanup::new(&cx);
        let app = app_with_visible_local_session(&mut cx, root.path(), "source");
        let cx = session_focus_test_window(&mut cx, &app);

        cx.update(|_window, cx| {
            app.update(cx, |app, cx| {
                // A local shell never recovers, even if the reason looks like a lost link.
                app.maybe_begin_link_recovery("source", LOST, false, cx);
                assert!(!app.session.link_recovery().is_active("source"));

                make_ssh(app);
                for (reason, already_disconnected) in [
                    ("SSH channel exit status 0", false),
                    ("SSH channel EOF", false),
                    ("SSH channel closed by remote", false),
                    (LOST, true),
                ] {
                    app.maybe_begin_link_recovery("source", reason, already_disconnected, cx);
                    assert!(
                        !app.session.link_recovery().is_active("source"),
                        "{reason} / disconnected={already_disconnected}"
                    );
                }

                app.maybe_begin_link_recovery("source", LOST, false, cx);
                assert!(app.session.link_recovery().is_active("source"));
                assert!(app.session.link_recovery().is_waiting_for("source", 1));
            });
        });
    }

    #[test]
    fn the_setting_turns_automatic_recovery_off() {
        let root = TestConfigDir::new("nyaterm-link-recovery-setting");
        let mut cx = TestAppContext::single();
        let _cleanup = crate::test_support::TestAppCleanup::new(&cx);
        let app = app_with_visible_local_session(&mut cx, root.path(), "source");
        let cx = session_focus_test_window(&mut cx, &app);

        cx.update(|_window, cx| {
            app.update(cx, |app, cx| {
                make_ssh(app);
                assert!(
                    app.settings.summary().terminal_auto_reconnect,
                    "on by default"
                );
                app.settings.toggle_terminal_auto_reconnect();

                app.maybe_begin_link_recovery("source", LOST, false, cx);

                assert!(!app.session.link_recovery().is_active("source"));
            });
        });
    }

    #[test]
    fn a_due_attempt_reconnects_and_a_network_failure_schedules_the_next_one() {
        let root = TestConfigDir::new("nyaterm-link-recovery-retry");
        let mut cx = TestAppContext::single();
        let _cleanup = crate::test_support::TestAppCleanup::new(&cx);
        let app = app_with_visible_local_session(&mut cx, root.path(), "source");
        let cx = session_focus_test_window(&mut cx, &app);

        cx.update(|_window, cx| {
            app.update(cx, |app, cx| {
                make_ssh(app);
                app.mark_session_disconnected("source", cx);
                app.maybe_begin_link_recovery("source", LOST, false, cx);

                app.run_link_recovery_attempt("source".into(), 1, cx);
                assert!(app.session.start_reconnect_is_pending("source"));
                assert!(!app.session.link_recovery().is_waiting_for("source", 1));

                app.link_recovery_attempt_failed("source", "Connection refused", cx);
                assert!(app.session.link_recovery().is_waiting_for("source", 2));
            });
        });
    }

    #[test]
    fn a_rejected_credential_stops_recovery_instead_of_retrying() {
        let root = TestConfigDir::new("nyaterm-link-recovery-auth");
        let mut cx = TestAppContext::single();
        let _cleanup = crate::test_support::TestAppCleanup::new(&cx);
        let app = app_with_visible_local_session(&mut cx, root.path(), "source");
        let cx = session_focus_test_window(&mut cx, &app);

        cx.update(|_window, cx| {
            app.update(cx, |app, cx| {
                make_ssh(app);
                app.mark_session_disconnected("source", cx);
                app.maybe_begin_link_recovery("source", LOST, false, cx);
                app.run_link_recovery_attempt("source".into(), 1, cx);

                app.link_recovery_attempt_failed("source", "Authentication failed", cx);

                assert!(!app.session.link_recovery().is_active("source"));
            });
        });
    }

    #[test]
    fn manual_reconnect_cancels_the_pending_automatic_attempt() {
        let root = TestConfigDir::new("nyaterm-link-recovery-manual");
        let mut cx = TestAppContext::single();
        let _cleanup = crate::test_support::TestAppCleanup::new(&cx);
        let app = app_with_visible_local_session(&mut cx, root.path(), "source");
        let cx = session_focus_test_window(&mut cx, &app);

        cx.update(|window, cx| {
            app.update(cx, |app, cx| {
                make_ssh(app);
                app.mark_session_disconnected("source", cx);
                app.maybe_begin_link_recovery("source", LOST, false, cx);

                app.reconnect_session("source".into(), window, cx);

                assert!(!app.session.link_recovery().is_active("source"));
                // The timer that was already scheduled must now do nothing.
                app.run_link_recovery_attempt("source".into(), 1, cx);
                assert!(app.session.start_reconnect_is_pending("source"));
                assert!(!app.session.link_recovery().is_active("source"));
            });
        });
    }

    #[test]
    fn a_stale_timer_does_not_reconnect_a_session_the_user_closed() {
        let root = TestConfigDir::new("nyaterm-link-recovery-stale");
        let mut cx = TestAppContext::single();
        let _cleanup = crate::test_support::TestAppCleanup::new(&cx);
        let app = app_with_visible_local_session(&mut cx, root.path(), "source");
        let cx = session_focus_test_window(&mut cx, &app);

        cx.update(|_window, cx| {
            app.update(cx, |app, cx| {
                make_ssh(app);
                app.mark_session_disconnected("source", cx);
                app.maybe_begin_link_recovery("source", LOST, false, cx);

                app.remove_session_state("source", cx);
                app.run_link_recovery_attempt("source".into(), 1, cx);

                assert!(!app.session.start_reconnect_is_pending("source"));
                assert!(!app.session.link_recovery().is_active("source"));
            });
        });
    }
}

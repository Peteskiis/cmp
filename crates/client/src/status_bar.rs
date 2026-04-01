use std::time::{Duration, Instant};

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

const TYPING_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHENTICATED_TIMEOUT: Duration = Duration::from_secs(5);

/// Transient connection lifecycle state displayed in the status bar.
#[non_exhaustive]
pub(crate) enum ConnectionStatus {
    Connecting,
    Authenticating,
    Authenticated(Instant),
    AuthFailed(String),
    Disconnected,
}

/// A single-line status bar showing transient connection and typing state.
///
/// Rendered above the dark input area — never flushed to scrollback.
pub(crate) struct StatusBar {
    connection: Option<ConnectionStatus>,
    typing: Option<(String, Instant)>,
}

impl StatusBar {
    pub(crate) const fn new() -> Self {
        Self {
            connection: None,
            typing: None,
        }
    }

    pub(crate) fn set_connection(&mut self, status: ConnectionStatus) {
        self.connection = Some(status);
    }

    pub(crate) fn set_typing(&mut self, who: String) {
        self.typing = Some((who, Instant::now()));
    }

    pub(crate) fn clear_typing(&mut self) {
        self.typing = None;
    }

    /// Returns `true` when there is expirable state that needs periodic refresh.
    pub(crate) const fn needs_tick(&self) -> bool {
        if self.typing.is_some() {
            return true;
        }
        matches!(self.connection, Some(ConnectionStatus::Authenticated(_)))
    }

    /// Expire stale state. Call from the tick handler.
    pub(crate) fn tick(&mut self) {
        if let Some((_, ts)) = &self.typing
            && ts.elapsed() > TYPING_TIMEOUT
        {
            self.typing = None;
        }
        if let Some(ConnectionStatus::Authenticated(ts)) = &self.connection
            && ts.elapsed() > AUTHENTICATED_TIMEOUT
        {
            self.connection = None;
        }
    }

    /// Render the status bar into a 1-row area (no dark background).
    pub(crate) fn render(&self, area: Rect, buf: &mut Buffer) {
        let conn = self.connection_span();
        let typing = self.typing_span();

        let line = match (conn, typing) {
            (Some(c), Some(t)) => {
                let gap = "  ";
                Line::from(vec![Span::raw("  "), c, Span::raw(gap), t])
            }
            (Some(c), None) => Line::from(vec![Span::raw("  "), c]),
            (None, Some(t)) => Line::from(vec![Span::raw("  "), t]),
            (None, None) => Line::from(""),
        };

        Paragraph::new(line).render(area, buf);
    }

    fn connection_span(&self) -> Option<Span<'_>> {
        let status = self.connection.as_ref()?;
        let (text, style) = match status {
            ConnectionStatus::Connecting => (
                "connecting...".to_owned(),
                Style::default().fg(Color::DarkGray),
            ),
            ConnectionStatus::Authenticating => (
                "connected, authenticating...".to_owned(),
                Style::default().fg(Color::DarkGray),
            ),
            ConnectionStatus::Authenticated(_) => (
                "authenticated \u{2713}".to_owned(),
                Style::default().fg(Color::DarkGray),
            ),
            ConnectionStatus::AuthFailed(reason) => (
                format!("auth failed: {reason}"),
                Style::default().fg(Color::Red),
            ),
            ConnectionStatus::Disconnected => (
                "disconnected, reconnecting...".to_owned(),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            ),
        };
        Some(Span::styled(text, style))
    }

    fn typing_span(&self) -> Option<Span<'static>> {
        let (who, ts) = self.typing.as_ref()?;
        if ts.elapsed() >= TYPING_TIMEOUT {
            return None;
        }
        Some(Span::styled(
            format!("{who} is typing..."),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        ))
    }
}

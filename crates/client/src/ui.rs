use std::io::{Stdout, stdout};
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::cursor::{Hide, Show};
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, KeyboardEnhancementFlags,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};
use ratatui::{Frame, Terminal};

use crate::app::{App, ChatEntry, Focus, Modal};

const ACCENT: Color = Color::Rgb(52, 211, 153);
const SENT: Color = Color::Rgb(110, 231, 183);
const MUTED: Color = Color::Rgb(120, 128, 140);
const BORDER: Color = Color::Rgb(70, 78, 90);
const MIN_WIDTH: u16 = 50;
const MIN_HEIGHT: u16 = 14;
const SIDEBAR_BREAKPOINT: u16 = 80;

pub(crate) type Term = Terminal<CrosstermBackend<Stdout>>;

/// Restores the user's terminal even when the application returns an error.
static TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);
static KEYBOARD_FLAGS_PUSHED: AtomicBool = AtomicBool::new(false);

pub(crate) struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    if !TERMINAL_ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }
    let _ = disable_raw_mode();
    if KEYBOARD_FLAGS_PUSHED.swap(false, Ordering::AcqRel) {
        let _ = execute!(stdout(), PopKeyboardEnhancementFlags);
    }
    let _ = execute!(stdout(), DisableBracketedPaste, Show, LeaveAlternateScreen);
}

pub(crate) fn init() -> anyhow::Result<(Term, TerminalGuard)> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        original_hook(info);
    }));

    enable_raw_mode()?;
    TERMINAL_ACTIVE.store(true, Ordering::Release);
    let guard = TerminalGuard;
    execute!(stdout(), EnterAlternateScreen, EnableBracketedPaste, Hide)?;
    if execute!(
        stdout(),
        PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
    )
    .is_ok()
    {
        KEYBOARD_FLAGS_PUSHED.store(true, Ordering::Release);
    }
    let terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    Ok((terminal, guard))
}

pub(crate) fn draw(terminal: &mut Term, app: &mut App) -> anyhow::Result<()> {
    terminal.draw(|frame| render(frame, app))?;
    Ok(())
}

fn render(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area);
        return;
    }

    let show_sidebar = area.width >= SIDEBAR_BREAKPOINT;
    if !show_sidebar && app.focus == Focus::Conversations {
        app.focus = Focus::Composer;
    }
    let columns = if show_sidebar {
        Layout::horizontal([Constraint::Length(26), Constraint::Min(24)]).split(area)
    } else {
        Layout::horizontal([Constraint::Length(0), Constraint::Min(1)]).split(area)
    };

    if show_sidebar {
        render_conversations(frame, columns[0], app);
    }
    render_chat(frame, columns[1], app, show_sidebar);
    render_modal(frame, app);
}

fn render_too_small(frame: &mut Frame<'_>, area: Rect) {
    let message = Paragraph::new(vec![
        Line::from("CMP needs a little more room").style(Style::default().bold()),
        Line::from(format!("minimum: {MIN_WIDTH}x{MIN_HEIGHT}")).style(Style::default().fg(MUTED)),
    ])
    .alignment(Alignment::Center)
    .block(Block::bordered().title(" CMP "));
    frame.render_widget(message, area);
}

fn render_conversations(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let peers = app.conversations();
    let items = peers.iter().map(|peer| {
        let is_self = peer == app.user_id.as_str();
        let verified = app
            .db
            .as_ref()
            .and_then(|db| crate::db::get_verification(db, peer))
            .is_some();
        let unread = app.unread_messages.get(peer).map_or(0, Vec::len);
        let label = if is_self { "Note to self" } else { peer };
        let warning = app.identity_warnings.contains_key(peer);
        let suffix = match (warning, verified, unread) {
            (true, _, 0) => "  !".to_owned(),
            (true, _, count) => format!("  ! {count}"),
            (false, true, 0) => "  ✓".to_owned(),
            (false, true, count) => format!("  ✓ {count}"),
            (false, false, 0) => String::new(),
            (false, false, count) => format!("  {count}"),
        };
        ListItem::new(Line::from(vec![
            Span::raw(label.to_owned()),
            Span::styled(
                suffix,
                Style::default().fg(if warning { Color::Red } else { ACCENT }),
            ),
        ]))
    });
    let border_style = if app.focus == Focus::Conversations {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(BORDER)
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::RIGHT)
                .border_style(border_style)
                .title(" Conversations ")
                .title_bottom(" n new "),
        )
        .highlight_style(Style::default().bg(Color::Rgb(42, 48, 58)).bold())
        .highlight_symbol("› ");
    let selected = app
        .selected_conversation
        .as_ref()
        .and_then(|selected| peers.iter().position(|peer| peer == selected))
        .unwrap_or(0);
    let mut state = ListState::default().with_selected((!peers.is_empty()).then_some(selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_chat(frame: &mut Frame<'_>, area: Rect, app: &mut App, show_sidebar: bool) {
    let composer_style = if app.focus == Focus::Composer && app.modal.is_none() {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(BORDER)
    };
    app.composer.set_block(
        Block::bordered()
            .border_style(composer_style)
            .title(" Message "),
    );
    let composer_height = app.composer.measure(area.width).preferred_rows.max(3);
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(composer_height),
        Constraint::Length(1),
    ])
    .split(area);

    render_header(frame, rows[0], app);
    render_messages(frame, rows[1], app);
    render_status(frame, rows[2], app);
    frame.render_widget(&app.composer, rows[3]);
    render_footer(frame, rows[4], show_sidebar);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let (title, subtitle) = app.target_user.as_ref().map_or_else(
        || {
            (
                "No conversation".to_owned(),
                "Choose or start a conversation".to_owned(),
            )
        },
        |target| {
            let peer = target.as_str();
            let title = if peer == app.user_id.as_str() {
                "Note to self".to_owned()
            } else {
                peer.to_owned()
            };
            let subtitle = if peer == app.user_id.as_str() {
                "private notes on this device".to_owned()
            } else if app.identity_warnings.contains_key(peer) {
                "security alert: identity key changed".to_owned()
            } else if app.crypto.has_session(peer) {
                "end-to-end encrypted".to_owned()
            } else {
                "establishing encrypted session".to_owned()
            };
            (title, subtitle)
        },
    );
    let has_warning = app
        .target_user
        .as_ref()
        .is_some_and(|target| app.identity_warnings.contains_key(target.as_str()));
    let subtitle_style = if has_warning {
        Style::default().fg(Color::Red).bold()
    } else {
        Style::default().fg(MUTED)
    };
    let header = Paragraph::new(vec![
        Line::from(title).style(Style::default().bold()),
        Line::from(subtitle).style(subtitle_style),
    ])
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(BORDER),
    );
    frame.render_widget(header, area);
}

fn render_messages(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let inner = area.inner(Margin::new(2, 0));
    if app.target_user.is_none() {
        app.last_rendered_max_scroll = None;
        let empty = Paragraph::new("Press Ctrl+N to start a conversation")
            .alignment(Alignment::Center)
            .style(Style::default().fg(MUTED));
        frame.render_widget(empty, inner);
        return;
    }

    let text = message_text(&app.chat_history);
    let paragraph = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .block(Block::default());
    let content_rows = paragraph.line_count(inner.width);
    let visible_rows = inner.height as usize;
    let max_scroll = content_rows.saturating_sub(visible_rows);
    if app.message_scroll > 0
        && let Some(previous_max) = app.last_rendered_max_scroll
    {
        app.message_scroll = app
            .message_scroll
            .saturating_add(max_scroll.saturating_sub(previous_max));
    }
    app.message_scroll = app.message_scroll.min(max_scroll);
    app.last_rendered_max_scroll = Some(max_scroll);
    let top = max_scroll.saturating_sub(app.message_scroll);
    #[allow(clippy::cast_possible_truncation)]
    let top = top.min(u16::MAX as usize) as u16;
    frame.render_widget(paragraph.scroll((top, 0)), inner);

    if content_rows > visible_rows {
        let mut state = ScrollbarState::new(max_scroll).position(top as usize);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            area,
            &mut state,
        );
    }
}

fn message_text(history: &[ChatEntry]) -> Text<'static> {
    let mut lines = Vec::new();
    for entry in history {
        if !lines.is_empty() {
            lines.push(Line::from(""));
        }
        match entry {
            ChatEntry::Sent(text) => {
                lines.push(
                    Line::from("You")
                        .alignment(Alignment::Right)
                        .style(Style::default().fg(SENT).bold()),
                );
                lines.extend(text.split('\n').map(|part| {
                    Line::from(part.to_owned())
                        .alignment(Alignment::Right)
                        .style(Style::default().fg(Color::White))
                }));
            }
            ChatEntry::Received { sender, text } => {
                lines.push(Line::from(sender.clone()).style(Style::default().fg(ACCENT).bold()));
                lines.extend(text.split('\n').map(|part| Line::from(part.to_owned())));
            }
            ChatEntry::Status(text) => lines.push(
                Line::from(text.clone())
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(MUTED)),
            ),
            ChatEntry::Warning(text) => lines.push(
                Line::from(format!("⚠ {text}"))
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Red).bold()),
            ),
        }
    }
    Text::from(lines)
}

fn render_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if let Some(notice) = app.notice_text() {
        frame.render_widget(
            Paragraph::new(Line::from(notice.to_owned()).style(Style::default().fg(MUTED))),
            area,
        );
    } else {
        app.status_bar.render(area, frame.buffer_mut());
    }
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, show_sidebar: bool) {
    let footer = if area.width < 60 {
        " Ctrl+N new  Enter send  F1 help"
    } else if show_sidebar {
        " Enter send  Shift+Enter newline  PgUp/PgDn scroll  F1 help"
    } else {
        " Ctrl+N new  Enter send  Shift+Enter newline  F1 help"
    };
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(MUTED)),
        area,
    );
}

fn render_modal(frame: &mut Frame<'_>, app: &mut App) {
    let dimensions = match app.modal.as_ref() {
        Some(Modal::NewChat(_)) => (62, 5),
        Some(Modal::Help | Modal::Verification(_)) => (62, 16),
        None => return,
    };
    let Some(modal) = &mut app.modal else {
        return;
    };
    let area = centered_rect(frame.area(), dimensions.0, dimensions.1);
    frame.render_widget(Clear, area);
    match modal {
        Modal::NewChat(input) => {
            input.set_block(
                Block::bordered()
                    .border_style(Style::default().fg(ACCENT))
                    .title(" New conversation ")
                    .title_bottom(" Enter open  Esc cancel "),
            );
            input.set_placeholder_text("username");
            frame.render_widget(&**input, area);
        }
        Modal::Help => render_help(frame, area),
        Modal::Verification(entries) => render_verification(frame, area, entries),
    }
}

fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let help = Paragraph::new(vec![
        Line::from("Tab / Esc       move focus"),
        Line::from("↑ / ↓           choose conversation"),
        Line::from("n               new conversation"),
        Line::from("Ctrl+N          new conversation from anywhere"),
        Line::from("Enter           open or send"),
        Line::from("Shift+Enter     newline"),
        Line::from("PageUp/PageDown scroll messages"),
        Line::from("End             newest message"),
        Line::from("v / F2          verify contact"),
        Line::from("Ctrl+C/Ctrl+D   quit"),
    ])
    .block(
        Block::bordered()
            .border_style(Style::default().fg(ACCENT))
            .title(" Keyboard help ")
            .title_bottom(" Esc close "),
    );
    frame.render_widget(help, area);
}

fn render_verification(frame: &mut Frame<'_>, area: Rect, entries: &[ChatEntry]) {
    let content = message_text(entries);
    let view = Paragraph::new(content).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .border_style(Style::default().fg(ACCENT))
            .title(" Safety number ")
            .title_bottom(" y confirm  x clear  Esc close "),
    );
    frame.render_widget(view, area);
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(4));
    let height = height.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;

    use super::*;

    fn make_app() -> (App, tempfile::TempDir) {
        let data_dir = tempfile::tempdir().unwrap();
        let crypto = crate::crypto_mgr::CryptoManager::load_or_generate(data_dir.path()).unwrap();
        let user = protocol::UserId::new("alice").unwrap();
        (App::new(user, crypto, None), data_dir)
    }

    fn render_text(app: &mut App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn wide_layout_renders_conversations_and_composer() {
        let (mut app, _dir) = make_app();
        let screen = render_text(&mut app, 100, 28);

        assert!(screen.contains("Conversations"));
        assert!(screen.contains("Note to self"));
        assert!(screen.contains("No conversation"));
        assert!(screen.contains("Press Ctrl+N to start a conversation"));
        assert!(screen.contains("Write a message"));
    }

    #[test]
    fn narrow_layout_keeps_chat_usable_without_sidebar() {
        let (mut app, _dir) = make_app();
        let screen = render_text(&mut app, 70, 22);

        assert!(!screen.contains("Conversations"));
        assert!(screen.contains("No conversation"));
        assert!(screen.contains("Press Ctrl+N to start a conversation"));
        assert!(screen.contains("Write a message"));
    }

    #[test]
    fn active_chat_renders_sent_received_and_warning_entries() {
        let (mut app, _dir) = make_app();
        app.target_user = Some(protocol::UserId::new("bob").unwrap());
        app.chat_history.push(ChatEntry::Received {
            sender: "bob".to_owned(),
            text: "hello".to_owned(),
        });
        app.chat_history.push(ChatEntry::Sent("hi back".to_owned()));
        app.chat_history
            .push(ChatEntry::Warning("identity changed".to_owned()));
        let screen = render_text(&mut app, 100, 28);

        assert!(screen.contains("bob"));
        assert!(screen.contains("hello"));
        assert!(screen.contains("hi back"));
        assert!(screen.contains("identity changed"));
    }

    #[test]
    fn too_small_terminal_shows_clear_requirement() {
        let (mut app, _dir) = make_app();
        let screen = render_text(&mut app, 40, 10);
        assert!(screen.contains("CMP needs a little more room"));
        assert!(screen.contains("minimum: 50x14"));
    }

    #[test]
    fn incoming_content_preserves_scrolled_viewport_anchor() {
        let (mut app, _dir) = make_app();
        app.target_user = Some(protocol::UserId::new("bob").unwrap());
        for index in 0..20 {
            app.chat_history.push(ChatEntry::Received {
                sender: "bob".to_owned(),
                text: format!("message {index}"),
            });
        }
        let _ = render_text(&mut app, 70, 22);
        app.message_scroll = 5;
        let previous_max = app.last_rendered_max_scroll.unwrap();

        app.chat_history.push(ChatEntry::Received {
            sender: "bob".to_owned(),
            text: "new message".to_owned(),
        });
        let _ = render_text(&mut app, 70, 22);

        let growth = app.last_rendered_max_scroll.unwrap() - previous_max;
        assert_eq!(app.message_scroll, 5 + growth);
    }
}

//! Keyboard event handling: key dispatch, input editing, history navigation.

use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyModifiers};
use protocol::ClientMessage;
use tokio::sync::mpsc;

use crate::app::App;
use crate::command_popup::PopupAction;
use crate::ui;

#[allow(
    clippy::cognitive_complexity,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]
pub(crate) fn handle_key_event(
    app: &mut App,
    terminal: &ui::Term,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    event: Event,
) -> anyhow::Result<()> {
    if let Event::Paste(text) = event {
        let byte_pos = app
            .input
            .char_indices()
            .nth(app.cursor_pos)
            .map_or(app.input.len(), |(i, _)| i);
        app.input.insert_str(byte_pos, &text);
        app.cursor_pos += text.chars().count();
        app.history_index = None;
        app.sync_command_popup();
        return Ok(());
    }
    let Event::Key(key) = event else {
        return Ok(());
    };

    // Intercept keys when the command popup is active
    if let Some(popup) = &mut app.command_popup {
        match popup.handle_key(key.code) {
            PopupAction::Consumed => return Ok(()),
            PopupAction::Complete(text) => {
                app.input = text;
                app.cursor_pos = app.input.chars().count();
                app.command_popup = None;
                return Ok(());
            }
            PopupAction::Submit(text) => {
                app.input = text;
                app.cursor_pos = app.input.chars().count();
                app.command_popup = None;
                // Fall through to Enter handling below
            }
            PopupAction::Dismiss => {
                app.command_popup = None;
                return Ok(());
            }
            PopupAction::PassThrough => {} // continue to normal key handling
        }
    }

    match (key.code, key.modifiers) {
        (KeyCode::Char('d'), KeyModifiers::CONTROL) => {
            app.running = false;
        }
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            if app.input.is_empty() {
                app.running = false;
            } else {
                app.discard_input();
            }
        }
        // Plain Enter → submit
        (KeyCode::Enter, KeyModifiers::NONE) => {
            crate::app::handle_enter(app, outgoing_tx)?;
        }
        // Modified Enter (Shift/Alt) or Ctrl+J → insert newline
        (KeyCode::Enter, _) | (KeyCode::Char('j'), KeyModifiers::CONTROL) => {
            app.insert_at_cursor('\n');
        }
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
            if app.cursor_pos > 0 {
                let target = line_start_pos(&app.input, app.cursor_pos);
                delete_char_range(app, target, app.cursor_pos);
            }
        }
        (KeyCode::Backspace, m) if m.contains(KeyModifiers::ALT) => {
            if app.cursor_pos > 0 {
                let old = app.cursor_pos;
                word_jump_left(app);
                delete_char_range(app, app.cursor_pos, old);
            }
        }
        (KeyCode::Backspace, _) => {
            if app.cursor_pos > 0 {
                delete_char_range(app, app.cursor_pos - 1, app.cursor_pos);
            }
        }
        // Alt+Left or Alt+b: jump word left
        (KeyCode::Left, m) if m.contains(KeyModifiers::ALT) => {
            word_jump_left(app);
        }
        (KeyCode::Char('b'), KeyModifiers::ALT) => {
            word_jump_left(app);
        }
        // Alt+Right or Alt+f: jump word right
        (KeyCode::Right, m) if m.contains(KeyModifiers::ALT) => {
            word_jump_right(app);
        }
        (KeyCode::Char('f'), KeyModifiers::ALT) => {
            word_jump_right(app);
        }
        // Ctrl+A / Home: start of current line
        (KeyCode::Char('a'), KeyModifiers::CONTROL) | (KeyCode::Home, _) => {
            app.cursor_pos = line_start_pos(&app.input, app.cursor_pos);
        }
        (KeyCode::Char('e'), KeyModifiers::CONTROL) | (KeyCode::End, _) => {
            app.cursor_pos = line_end_pos(&app.input, app.cursor_pos);
        }
        (KeyCode::Left, _) => {
            if app.cursor_pos > 0 {
                app.cursor_pos -= 1;
            }
        }
        (KeyCode::Right, _) => {
            if app.cursor_pos < app.input.chars().count() {
                app.cursor_pos += 1;
            }
        }
        (KeyCode::Up, _) => {
            let width = terminal.size()?.width as usize;
            let max_cols = width.saturating_sub(ui::PREFIX_WIDTH);
            let (lines, starts) = ui::wrap_input(&app.input, max_cols);
            let (row, col) = ui::cursor_visual_pos(app.cursor_pos, &starts);
            if row > 0 {
                app.cursor_pos = ui::visual_to_cursor(row - 1, col, &starts, &lines);
            } else {
                history_back(app);
            }
        }
        (KeyCode::Down, _) => {
            let width = terminal.size()?.width as usize;
            let max_cols = width.saturating_sub(ui::PREFIX_WIDTH);
            let (lines, starts) = ui::wrap_input(&app.input, max_cols);
            let (row, col) = ui::cursor_visual_pos(app.cursor_pos, &starts);
            if row + 1 < lines.len() {
                app.cursor_pos = ui::visual_to_cursor(row + 1, col, &starts, &lines);
            } else {
                history_forward(app);
            }
        }
        (KeyCode::Char(c), mods) if mods.is_empty() || mods == KeyModifiers::SHIFT => {
            app.insert_at_cursor(c);

            // Send typing indicator (debounced, only if session exists)
            if let Some(ref target) = app.target_user
                && target.as_str() != app.user_id.as_str()
                && app.crypto.has_session(target.as_str())
            {
                let now = Instant::now();
                let should_send = app
                    .last_typing_sent
                    .is_none_or(|t| now.duration_since(t) > Duration::from_secs(3));
                if should_send {
                    let _ = outgoing_tx.send(ClientMessage::Typing {
                        recipient_id: target.clone(),
                    });
                    app.last_typing_sent = Some(now);
                }
            }
        }
        _ => {}
    }
    // Exit history browsing only on keys that actually mutate input.
    // Ctrl+A/E, Alt+b/f are navigation — they should not exit history mode.
    let is_edit_key = matches!(
        (key.code, key.modifiers),
        (KeyCode::Char(_), m) if m.is_empty() || m == KeyModifiers::SHIFT
    ) || matches!(
        key.code,
        KeyCode::Backspace | KeyCode::Delete | KeyCode::Enter | KeyCode::Tab
    ) || matches!(
        (key.code, key.modifiers),
        (KeyCode::Char('u' | 'j'), KeyModifiers::CONTROL)
    );
    if app.history_index.is_some() && is_edit_key {
        app.history_index = None;
    }
    // Don't show the command popup while browsing history — it would
    // intercept up/down arrows and block further history navigation.
    if app.history_index.is_some() {
        app.command_popup = None;
    } else {
        app.sync_command_popup();
    }
    Ok(())
}

/// Delete characters in `[from, to)` by char index and set cursor to `from`.
fn delete_char_range(app: &mut App, from: usize, to: usize) {
    let start_byte = app
        .input
        .char_indices()
        .nth(from)
        .map_or(app.input.len(), |(i, _)| i);
    let end_byte = app
        .input
        .char_indices()
        .nth(to)
        .map_or(app.input.len(), |(i, _)| i);
    app.input.replace_range(start_byte..end_byte, "");
    app.cursor_pos = from;
}

fn line_start_pos(input: &str, cursor: usize) -> usize {
    let chars: Vec<char> = input.chars().collect();
    let mut pos = cursor;
    while pos > 0 && chars[pos - 1] != '\n' {
        pos -= 1;
    }
    pos
}

fn line_end_pos(input: &str, cursor: usize) -> usize {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut pos = cursor;
    while pos < len && chars[pos] != '\n' {
        pos += 1;
    }
    pos
}

fn word_jump_left(app: &mut App) {
    let chars: Vec<char> = app.input.chars().collect();
    let mut pos = app.cursor_pos;
    while pos > 0 && chars[pos - 1].is_whitespace() {
        pos -= 1;
    }
    while pos > 0 && !chars[pos - 1].is_whitespace() {
        pos -= 1;
    }
    app.cursor_pos = pos;
}

fn word_jump_right(app: &mut App) {
    let chars: Vec<char> = app.input.chars().collect();
    let len = chars.len();
    let mut pos = app.cursor_pos;
    while pos < len && !chars[pos].is_whitespace() {
        pos += 1;
    }
    while pos < len && chars[pos].is_whitespace() {
        pos += 1;
    }
    app.cursor_pos = pos;
}

fn history_back(app: &mut App) {
    if app.input_history.is_empty() {
        return;
    }
    let new_idx = match app.history_index {
        None => {
            app.history_draft = app.input.clone();
            app.input_history.len() - 1
        }
        Some(0) => return,
        Some(i) => i - 1,
    };
    app.history_index = Some(new_idx);
    app.input.clone_from(&app.input_history[new_idx]);
    app.cursor_pos = app.input.chars().count();
    app.input_scroll = 0;
}

fn history_forward(app: &mut App) {
    let Some(idx) = app.history_index else {
        return;
    };
    if idx + 1 < app.input_history.len() {
        let new_idx = idx + 1;
        app.history_index = Some(new_idx);
        app.input.clone_from(&app.input_history[new_idx]);
    } else {
        app.history_index = None;
        app.input.clone_from(&app.history_draft);
        app.history_draft.clear();
    }
    app.cursor_pos = app.input.chars().count();
    app.input_scroll = 0;
}

pub(crate) fn show_keybindings(app: &mut App) {
    app.status("keyboard shortcuts:");
    app.status("  Enter          send message");
    app.status("  Shift+Enter    insert newline");
    app.status("  Up / Down      input history");
    app.status("  Ctrl+C         clear input / quit");
    app.status("  Ctrl+D         quit");
    app.status("  Ctrl+A         start of line");
    app.status("  Ctrl+E         end of line");
    app.status("  Ctrl+U         delete to line start");
    app.status("  Alt+Backspace  delete word");
    app.status("  Alt+b / Alt+f  jump word left / right");
    app.status("  Ctrl+J         insert newline (alt)");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app() -> App {
        let uid = protocol::UserId::new("testuser").unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let crypto = crate::crypto_mgr::CryptoManager::load_or_generate(data_dir.path()).unwrap();
        App::new(uid, crypto, None)
    }

    #[test]
    fn line_start_pos_single_line() {
        assert_eq!(line_start_pos("hello world", 5), 0);
        assert_eq!(line_start_pos("hello world", 0), 0);
    }

    #[test]
    fn line_start_pos_multiline() {
        assert_eq!(line_start_pos("first\nsecond\nthird", 8), 6);
        assert_eq!(line_start_pos("first\nsecond\nthird", 6), 6);
    }

    #[test]
    fn line_end_pos_single_line() {
        assert_eq!(line_end_pos("hello world", 5), 11);
        assert_eq!(line_end_pos("hello world", 11), 11);
    }

    #[test]
    fn line_end_pos_multiline() {
        assert_eq!(line_end_pos("first\nsecond\nthird", 2), 5);
        assert_eq!(line_end_pos("first\nsecond\nthird", 8), 12);
    }

    #[test]
    fn word_jump_left_basics() {
        let mut app = make_app();
        app.input = "hello world foo".into();
        app.cursor_pos = 15;
        word_jump_left(&mut app);
        assert_eq!(app.cursor_pos, 12);
        word_jump_left(&mut app);
        assert_eq!(app.cursor_pos, 6);
        word_jump_left(&mut app);
        assert_eq!(app.cursor_pos, 0);
        word_jump_left(&mut app);
        assert_eq!(app.cursor_pos, 0);
    }

    #[test]
    fn word_jump_right_basics() {
        let mut app = make_app();
        app.input = "hello world foo".into();
        app.cursor_pos = 0;
        word_jump_right(&mut app);
        assert_eq!(app.cursor_pos, 6);
        word_jump_right(&mut app);
        assert_eq!(app.cursor_pos, 12);
        word_jump_right(&mut app);
        assert_eq!(app.cursor_pos, 15);
    }

    #[test]
    fn delete_char_range_middle() {
        let mut app = make_app();
        app.input = "abcdef".into();
        app.cursor_pos = 4;
        delete_char_range(&mut app, 2, 4);
        assert_eq!(app.input, "abef");
        assert_eq!(app.cursor_pos, 2);
    }

    #[test]
    fn delete_char_range_single() {
        let mut app = make_app();
        app.input = "abc".into();
        app.cursor_pos = 2;
        delete_char_range(&mut app, 1, 2);
        assert_eq!(app.input, "ac");
        assert_eq!(app.cursor_pos, 1);
    }

    #[test]
    fn history_back_forward_cycle() {
        let mut app = make_app();
        app.input = "first".into();
        app.clear_input();
        app.input = "second".into();
        app.clear_input();
        app.input = "current draft".into();

        // Up → second
        history_back(&mut app);
        assert_eq!(app.input, "second");
        assert!(app.history_index.is_some());

        // Up → first
        history_back(&mut app);
        assert_eq!(app.input, "first");

        // Up at oldest → stays
        history_back(&mut app);
        assert_eq!(app.input, "first");

        // Down → second
        history_forward(&mut app);
        assert_eq!(app.input, "second");

        // Down past end → restore draft
        history_forward(&mut app);
        assert_eq!(app.input, "current draft");
        assert!(app.history_index.is_none());
    }

    #[test]
    fn history_empty_does_nothing() {
        let mut app = make_app();
        app.input = "some text".into();
        app.cursor_pos = 9;
        history_back(&mut app);
        assert_eq!(app.input, "some text");
        assert!(app.history_index.is_none());
    }

    #[test]
    fn history_dedup() {
        let mut app = make_app();
        app.input = "same".into();
        app.clear_input();
        app.input = "same".into();
        app.clear_input();
        assert_eq!(app.input_history.len(), 1);
    }

    #[test]
    fn discard_input_does_not_save() {
        let mut app = make_app();
        app.input = "discarded".into();
        app.discard_input();
        assert!(app.input_history.is_empty());
    }

    #[test]
    fn history_eviction_at_capacity() {
        let mut app = make_app();
        for i in 0..App::MAX_INPUT_HISTORY + 10 {
            app.input = format!("msg {i}");
            app.clear_input();
        }
        assert_eq!(app.input_history.len(), App::MAX_INPUT_HISTORY);
        assert_eq!(app.input_history[0], "msg 10");
    }
}

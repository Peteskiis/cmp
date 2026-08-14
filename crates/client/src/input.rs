//! Focus-aware keyboard and paste handling for the full-screen interface.

use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use protocol::ClientMessage;
use tokio::sync::mpsc;
use tui_textarea::{TextArea, WrapMode};

use crate::app::{App, Focus, Modal};

pub(crate) fn handle_key_event(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    event: Event,
) -> anyhow::Result<()> {
    match event {
        Event::Paste(text) => handle_paste(app, outgoing_tx, &text),
        Event::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
            handle_key(app, outgoing_tx, key)?;
        }
        _ => {}
    }
    Ok(())
}

fn handle_paste(app: &mut App, outgoing_tx: &mpsc::UnboundedSender<ClientMessage>, text: &str) {
    if let Some(Modal::NewChat(input)) = &mut app.modal {
        input.insert_str(text.replace(['\r', '\n'], ""));
        return;
    }
    if app.modal.is_none() && app.focus == Focus::Composer && app.composer.insert_str(text) {
        composer_changed(app, outgoing_tx);
    }
}

fn handle_key(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    key: KeyEvent,
) -> anyhow::Result<()> {
    if matches!(
        (key.code, key.modifiers),
        (KeyCode::Char('c' | 'd'), KeyModifiers::CONTROL)
    ) {
        app.running = false;
        return Ok(());
    }

    if app.modal.is_some() {
        handle_modal_key(app, outgoing_tx, key);
        return Ok(());
    }
    if key.code == KeyCode::Char('n') && key.modifiers == KeyModifiers::CONTROL {
        app.modal = Some(Modal::NewChat(new_chat_input()));
        return Ok(());
    }
    if key.code == KeyCode::F(2) {
        crate::app::show_verification(app, "view");
        return Ok(());
    }

    match key.code {
        KeyCode::F(1) => app.modal = Some(Modal::Help),
        KeyCode::PageUp => app.message_scroll = app.message_scroll.saturating_add(10),
        KeyCode::PageDown => app.message_scroll = app.message_scroll.saturating_sub(10),
        KeyCode::End if key.modifiers.is_empty() => app.message_scroll = 0,
        _ => match app.focus {
            Focus::Conversations => handle_conversation_key(app, outgoing_tx, key)?,
            Focus::Composer => handle_composer_key(app, outgoing_tx, key),
        },
    }
    Ok(())
}

fn handle_modal_key(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    key: KeyEvent,
) {
    if key.code == KeyCode::Esc {
        app.modal = None;
        return;
    }

    match app.modal.as_mut() {
        Some(Modal::NewChat(input)) => {
            if key.code == KeyCode::Enter && key.modifiers.is_empty() {
                let target = input.lines().join("").trim().to_owned();
                if target.is_empty() {
                    return;
                }
                app.modal = None;
                if let Err(error) = crate::app::open_conversation(app, outgoing_tx, &target) {
                    app.status(&format!("invalid username: {error}"));
                }
            } else {
                input.input(key);
            }
        }
        Some(Modal::Help) => {
            if matches!(key.code, KeyCode::F(1) | KeyCode::Char('?')) {
                app.modal = None;
            }
        }
        Some(Modal::Verification(_)) => match key.code {
            KeyCode::Char('y') => crate::app::show_verification(app, "confirm"),
            KeyCode::Char('x') => crate::app::show_verification(app, "clear"),
            _ => {}
        },
        None => {}
    }
}

fn handle_conversation_key(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    key: KeyEvent,
) -> anyhow::Result<()> {
    let peers = app.conversations();
    match key.code {
        KeyCode::Up => move_conversation_selection(app, &peers, -1),
        KeyCode::Down => move_conversation_selection(app, &peers, 1),
        KeyCode::Enter => {
            if let Some(peer) = &app.selected_conversation {
                let peer = peer.clone();
                crate::app::open_conversation(app, outgoing_tx, &peer)?;
            }
        }
        KeyCode::Tab | KeyCode::Esc => app.focus = Focus::Composer,
        KeyCode::Char('n') => app.modal = Some(Modal::NewChat(new_chat_input())),
        KeyCode::Char('?') => app.modal = Some(Modal::Help),
        KeyCode::Char('v') => crate::app::show_verification(app, "view"),
        KeyCode::Char('q') => app.running = false,
        _ => {}
    }
    Ok(())
}

fn handle_composer_key(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    key: KeyEvent,
) {
    match (key.code, key.modifiers) {
        (KeyCode::Tab | KeyCode::Esc, _) => {
            app.focus = Focus::Conversations;
            sync_conversation_cursor(app);
        }
        (KeyCode::Enter, KeyModifiers::NONE) => crate::app::handle_enter(app, outgoing_tx),
        (KeyCode::Enter, _) | (KeyCode::Char('j'), KeyModifiers::CONTROL) => {
            app.composer.insert_newline();
            composer_changed(app, outgoing_tx);
        }
        _ => {
            if app.composer.input(key) {
                composer_changed(app, outgoing_tx);
            }
        }
    }
}

fn new_chat_input() -> Box<TextArea<'static>> {
    let mut input = TextArea::default();
    input.set_wrap_mode(WrapMode::None);
    input.set_max_rows(3);
    input.set_tab_length(0);
    Box::new(input)
}

fn sync_conversation_cursor(app: &mut App) {
    app.selected_conversation = app
        .target_user
        .as_ref()
        .map(|active| active.as_str().to_owned())
        .or_else(|| app.conversations().first().cloned());
}

fn move_conversation_selection(app: &mut App, peers: &[String], offset: isize) {
    if peers.is_empty() {
        app.selected_conversation = None;
        return;
    }
    let current = app
        .selected_conversation
        .as_ref()
        .and_then(|selected| peers.iter().position(|peer| peer == selected))
        .unwrap_or(0);
    let next = current
        .saturating_add_signed(offset)
        .min(peers.len().saturating_sub(1));
    app.selected_conversation = peers.get(next).cloned();
}

fn composer_changed(app: &mut App, outgoing_tx: &mpsc::UnboundedSender<ClientMessage>) {
    app.notice = None;
    let Some(target) = &app.target_user else {
        return;
    };
    if target.as_str() == app.user_id.as_str() || !app.crypto.has_session(target.as_str()) {
        return;
    }
    let now = Instant::now();
    if app
        .last_typing_sent
        .is_none_or(|sent| now.duration_since(sent) > Duration::from_secs(3))
    {
        let _ = outgoing_tx.send(ClientMessage::Typing {
            recipient_id: target.clone(),
        });
        app.last_typing_sent = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app() -> (App, tempfile::TempDir) {
        let data_dir = tempfile::tempdir().unwrap();
        let crypto = crate::crypto_mgr::CryptoManager::load_or_generate(data_dir.path()).unwrap();
        let user = protocol::UserId::new("alice").unwrap();
        (App::new(user, crypto, None), data_dir)
    }

    #[test]
    fn new_chat_submission_flattens_unexpected_newlines() {
        let mut input = new_chat_input();
        input.insert_str("alice\nbob");
        assert_eq!(input.lines(), ["alice", "bob"]);
        let submitted = input.lines().join("");
        assert_eq!(submitted, "alicebob");
    }

    #[test]
    fn enter_without_conversation_preserves_draft() {
        let (mut app, _dir) = make_app();
        let (tx, _rx) = mpsc::unbounded_channel();
        app.composer.insert_str("do not lose me");

        handle_key_event(
            &mut app,
            &tx,
            Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        )
        .unwrap();

        assert_eq!(app.composer_text(), "do not lose me");
        assert_eq!(
            app.notice_text(),
            Some("choose a conversation before sending")
        );
    }

    #[test]
    fn shift_enter_inserts_newline_in_composer() {
        let (mut app, _dir) = make_app();
        let (tx, _rx) = mpsc::unbounded_channel();
        app.composer.insert_str("first line");

        handle_key_event(
            &mut app,
            &tx,
            Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT)),
        )
        .unwrap();

        assert_eq!(app.composer.lines(), ["first line", ""]);
    }

    #[test]
    fn control_n_opens_new_conversation_from_composer() {
        let (mut app, _dir) = make_app();
        let (tx, _rx) = mpsc::unbounded_channel();

        handle_key_event(
            &mut app,
            &tx,
            Event::Key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL)),
        )
        .unwrap();

        assert!(matches!(app.modal, Some(Modal::NewChat(_))));
    }

    #[test]
    fn conversation_selection_survives_database_reordering() {
        let data_dir = tempfile::tempdir().unwrap();
        let crypto = crate::crypto_mgr::CryptoManager::load_or_generate(data_dir.path()).unwrap();
        let db = crate::db::open(&data_dir.path().join("client.db")).unwrap();
        crate::db::insert_message(
            &db,
            "bob",
            crate::db::MessageDirection::Received,
            "m1",
            "hello",
        )
        .unwrap();
        let user = protocol::UserId::new("alice").unwrap();
        let mut app = App::new(user, crypto, Some(db));
        app.focus = Focus::Conversations;
        app.selected_conversation = Some("bob".to_owned());
        crate::db::insert_message(
            app.db.as_ref().unwrap(),
            "carol",
            crate::db::MessageDirection::Received,
            "m2",
            "newer",
        )
        .unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();

        handle_key_event(
            &mut app,
            &tx,
            Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        )
        .unwrap();

        assert_eq!(
            app.target_user.as_ref().map(protocol::UserId::as_str),
            Some("bob")
        );
    }

    #[test]
    fn pending_new_conversation_remains_visible_and_selectable() {
        let (mut app, _dir) = make_app();
        let (tx, _rx) = mpsc::unbounded_channel();
        crate::app::open_conversation(&mut app, &tx, "bob").unwrap();

        assert!(app.conversations().iter().any(|peer| peer == "bob"));
        assert_eq!(app.selected_conversation.as_deref(), Some("bob"));

        app.target_user = None;
        app.focus = Focus::Conversations;
        handle_key_event(
            &mut app,
            &tx,
            Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        )
        .unwrap();

        assert_eq!(
            app.target_user.as_ref().map(protocol::UserId::as_str),
            Some("bob")
        );
    }
}

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
use futures::StreamExt;
use protocol::{ClientMessage, MessageId, ServerMessage, UserId, consts};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;

use crate::crypto_mgr::CryptoManager;
use crate::{net, ui};

/// Events that flow into the main UI loop.
pub enum AppEvent {
    Connecting,
    Connected,
    Authenticated,
    AuthFailed(String),
    Disconnected,
    Server(ServerMessage),
}

/// A line of chat history rendered inside the viewport.
#[non_exhaustive]
pub(crate) enum ChatEntry {
    Sent(String),
    Received { sender: String, text: String },
    Status(String),
}

struct App {
    input: String,
    cursor_pos: usize,
    input_scroll: usize,
    target_user: Option<UserId>,
    running: bool,
    crypto: CryptoManager,
    last_typing_sent: Option<Instant>,
    peer_typing: Option<(String, Instant)>,
    pending_msg_ids: Vec<MessageId>,
    unread_messages: HashMap<String, Vec<MessageId>>,
    chat_history: Vec<ChatEntry>,
    db: Option<rusqlite::Connection>,
}

impl App {
    fn new(crypto: CryptoManager, db: Option<rusqlite::Connection>) -> Self {
        Self {
            input: String::new(),
            cursor_pos: 0,
            input_scroll: 0,
            target_user: None,
            running: true,
            crypto,
            last_typing_sent: None,
            peer_typing: None,
            pending_msg_ids: Vec::new(),
            unread_messages: HashMap::new(),
            chat_history: Vec::new(),
            db,
        }
    }

    fn status(&mut self, text: &str) {
        self.chat_history.push(ChatEntry::Status(text.to_owned()));
    }

    fn clear_input(&mut self) {
        self.input.clear();
        self.cursor_pos = 0;
        self.input_scroll = 0;
    }

    fn insert_at_cursor(&mut self, ch: char) {
        let byte_pos = self
            .input
            .char_indices()
            .nth(self.cursor_pos)
            .map_or(self.input.len(), |(i, _)| i);
        self.input.insert(byte_pos, ch);
        self.cursor_pos += 1;
    }
}

#[allow(clippy::cognitive_complexity)]
pub async fn run(user_id: &str, server_url: &str) -> anyhow::Result<()> {
    let validated_uid = UserId::new(user_id)?;

    let data_dir = dirs_data_dir(user_id);
    let mut crypto = CryptoManager::load_or_generate(&data_dir)?;

    if crypto.needs_registration() {
        match register_with_server(user_id, server_url, &mut crypto).await {
            Ok(()) => {}
            Err(e) => eprintln!("Registration failed: {e}"),
        }
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel::<ClientMessage>();

    let net_url = server_url.to_owned();
    let net_uid = validated_uid.clone();
    let net_identity = crypto::keys::IdentityKeyPair::from_bytes(&crypto.identity().to_bytes());
    tokio::spawn(async move {
        net::run(net_url, net_uid, &net_identity, event_tx, outgoing_rx).await;
    });

    let db = match crate::db::open(&data_dir.join("client.db")) {
        Ok(conn) => Some(conn),
        Err(e) => {
            tracing::warn!("failed to open message database: {e}");
            None
        }
    };

    // Print startup banner before raw mode (lands in terminal scrollback)
    print_banner(user_id, server_url);

    let (mut terminal, _guard) = ui::init()?;
    let mut app = App::new(crypto, db);
    if app.db.is_none() {
        app.status("warning: message history unavailable");
    }
    app.status("type /help for commands");
    let mut event_stream = EventStream::new();

    while app.running {
        let term_width = terminal.size()?.width as usize;
        let max_cols = term_width.saturating_sub(ui::PREFIX_WIDTH);
        let (visual_lines, line_starts) = ui::wrap_input(&app.input, max_cols);
        let (cursor_row, cursor_col) = ui::cursor_visual_pos(app.cursor_pos, &line_starts);

        // Vertical scroll: keep cursor visible
        let max_vis = ui::max_visible_input_lines();
        if cursor_row < app.input_scroll {
            app.input_scroll = cursor_row;
        } else if cursor_row >= app.input_scroll + max_vis {
            app.input_scroll = cursor_row - max_vis + 1;
        }

        let input_rows = visual_lines.len().max(2);
        let available_chat = ui::max_visible_input_lines().saturating_sub(input_rows);
        ui::flush_chat_to_scrollback(&mut terminal, &mut app.chat_history, available_chat)?;

        let typing_label = app
            .peer_typing
            .as_ref()
            .filter(|(_, ts)| ts.elapsed() < Duration::from_secs(5))
            .map(|(name, _)| name.as_str());
        ui::draw_input(
            &mut terminal,
            &app.chat_history,
            &visual_lines,
            cursor_row,
            cursor_col,
            app.input_scroll,
            typing_label,
        )?;

        let typing_tick = async {
            if app.peer_typing.is_some() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            Some(Ok(event)) = event_stream.next() => {
                handle_key_event(&mut app, &terminal, &outgoing_tx, event)?;
            }
            Some(event) = event_rx.recv() => {
                handle_app_event(&mut app, &outgoing_tx, event)?;
            }
            () = typing_tick => {
                if let Some((_, ts)) = &app.peer_typing
                    && ts.elapsed() > Duration::from_secs(5)
                {
                    app.peer_typing = None;
                }
            }
        }
    }

    Ok(())
}

fn print_banner(user_id: &str, server_url: &str) {
    // Truncate server URL for display
    let server_display = if server_url.len() > 40 {
        format!("{}...", &server_url[..37])
    } else {
        server_url.to_owned()
    };

    let title = ">_ Cluster Message Protocol (v0.1.0)";
    let user_line = format!("user:   {user_id}");
    let server_line = format!("server: {server_display}");

    let content_width = [title.len(), user_line.len(), server_line.len()]
        .into_iter()
        .max()
        .unwrap_or(0)
        + 2; // padding

    let pad = |s: &str| format!(" {s}{}", " ".repeat(content_width - s.len() - 1));

    println!(
        "\x1b[2m\u{256d}{}\u{256e}\x1b[0m",
        "\u{2500}".repeat(content_width)
    );
    println!(
        "\x1b[2m\u{2502}\x1b[0m\x1b[1m{}\x1b[0m\x1b[2m\u{2502}\x1b[0m",
        pad(title)
    );
    println!(
        "\x1b[2m\u{2502}{}\u{2502}\x1b[0m",
        " ".repeat(content_width)
    );
    println!(
        "\x1b[2m\u{2502}\x1b[0m{}\x1b[2m\u{2502}\x1b[0m",
        pad(&user_line)
    );
    println!(
        "\x1b[2m\u{2502}\x1b[0m{}\x1b[2m\u{2502}\x1b[0m",
        pad(&server_line)
    );
    println!(
        "\x1b[2m\u{2570}{}\u{256f}\x1b[0m",
        "\u{2500}".repeat(content_width)
    );
    println!();
}

fn dirs_data_dir(user_id: &str) -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    std::path::PathBuf::from(home).join(".cmp").join(user_id)
}

#[allow(clippy::cognitive_complexity, clippy::needless_pass_by_value)]
fn handle_key_event(
    app: &mut App,
    terminal: &ui::Term,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    event: Event,
) -> anyhow::Result<()> {
    let Event::Key(key) = event else {
        // Resize and other events — just let the loop redraw
        return Ok(());
    };

    match (key.code, key.modifiers) {
        (KeyCode::Char('d' | 'c'), KeyModifiers::CONTROL) => {
            app.running = false;
        }
        // Plain Enter → submit
        (KeyCode::Enter, KeyModifiers::NONE) => {
            handle_enter(app, outgoing_tx)?;
        }
        // Modified Enter (Shift/Alt) or Ctrl+J → insert newline
        (KeyCode::Enter, _) | (KeyCode::Char('j'), KeyModifiers::CONTROL) => {
            app.insert_at_cursor('\n');
        }
        (KeyCode::Backspace, _) => {
            if app.cursor_pos > 0 {
                let byte_pos = app
                    .input
                    .char_indices()
                    .nth(app.cursor_pos - 1)
                    .map_or(0, |(i, _)| i);
                let end_pos = app
                    .input
                    .char_indices()
                    .nth(app.cursor_pos)
                    .map_or(app.input.len(), |(i, _)| i);
                app.input.replace_range(byte_pos..end_pos, "");
                app.cursor_pos -= 1;
            }
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
            }
        }
        (KeyCode::Down, _) => {
            let width = terminal.size()?.width as usize;
            let max_cols = width.saturating_sub(ui::PREFIX_WIDTH);
            let (lines, starts) = ui::wrap_input(&app.input, max_cols);
            let (row, col) = ui::cursor_visual_pos(app.cursor_pos, &starts);
            if row + 1 < lines.len() {
                app.cursor_pos = ui::visual_to_cursor(row + 1, col, &starts, &lines);
            }
        }
        (KeyCode::Char(c), mods) if mods.is_empty() || mods == KeyModifiers::SHIFT => {
            app.insert_at_cursor(c);

            // Send typing indicator (debounced, only if session exists)
            if let Some(ref target) = app.target_user
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
    Ok(())
}

fn handle_enter(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
) -> anyhow::Result<()> {
    let text = app.input.trim().to_owned();
    if text.is_empty() {
        return Ok(());
    }

    // Slash commands
    if text.starts_with('/') {
        return handle_command(app, outgoing_tx, &text);
    }

    let Some(ref target) = app.target_user else {
        app.status("use /chat <username> first");
        app.clear_input();
        return Ok(());
    };
    let target_str = target.as_str();

    if !app.crypto.has_session(target_str) {
        app.status("waiting for session establishment...");
        app.clear_input();
        return Ok(());
    }

    // Check plaintext size BEFORE encrypting to avoid ratchet desync
    let estimated_b64_len = (text.len() + 18) / 3 * 4;
    if estimated_b64_len > consts::MAX_CIPHERTEXT_BYTES {
        app.status("message too long");
        app.clear_input();
        return Ok(());
    }

    let envelope = match app.crypto.encrypt(target_str, text.as_bytes()) {
        Ok(env) => env,
        Err(e) => {
            app.status(&format!("encrypt error: {e}"));
            app.clear_input();
            return Ok(());
        }
    };

    let msg_id = MessageId::new();
    // Cap pending IDs to prevent unbounded growth
    if app.pending_msg_ids.len() >= 10_000 {
        app.pending_msg_ids.clear();
    }
    app.pending_msg_ids.push(msg_id.clone());
    let _ = outgoing_tx.send(ClientMessage::SendMessage {
        recipient_id: target.clone(),
        message_id: msg_id.clone(),
        envelope,
    });
    if let Some(ref conn) = app.db
        && let Err(e) = crate::db::insert_message(
            conn,
            target_str,
            crate::db::MessageDirection::Sent,
            &msg_id.to_string(),
            &text,
        )
    {
        tracing::warn!("failed to persist sent message: {e}");
    }
    app.chat_history.push(ChatEntry::Sent(text));
    app.clear_input();
    Ok(())
}

#[allow(clippy::cognitive_complexity, clippy::unnecessary_wraps)]
fn handle_command(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    text: &str,
) -> anyhow::Result<()> {
    if text == "/contacts" || text == "/c" {
        let peers: Vec<String> = app
            .crypto
            .session_peers()
            .into_iter()
            .map(String::from)
            .collect();
        if peers.is_empty() {
            app.status("no contacts yet");
        } else {
            app.status(&format!("contacts ({})", peers.len()));
            for peer in &peers {
                let active = app
                    .target_user
                    .as_ref()
                    .is_some_and(|t| t.as_str() == peer.as_str());
                let marker = if active { " \u{25c0}" } else { "" };
                app.status(&format!("  {peer}{marker}"));
            }
        }
        app.clear_input();
        return Ok(());
    }

    if text == "/quit" || text == "/q" {
        app.running = false;
        app.clear_input();
        return Ok(());
    }

    if text == "/help" || text == "/h" {
        app.status("commands:");
        app.status("  /chat <user>  \u{2014} start or switch conversation");
        app.status("  /contacts     \u{2014} list all contacts");
        app.status("  /quit         \u{2014} exit");
        app.status("  /help         \u{2014} show this help");
        app.clear_input();
        return Ok(());
    }

    if text == "/chat" {
        app.status("usage: /chat <username>");
        app.clear_input();
        return Ok(());
    }

    if let Some(target) = text.strip_prefix("/chat ") {
        let target = target.trim();
        match UserId::new(target) {
            Ok(uid) => {
                // Clear viewport and load persisted history for this peer
                app.chat_history.clear();
                if let Some(ref conn) = app.db {
                    match crate::db::load_recent_messages(conn, target) {
                        Ok(messages) => {
                            app.chat_history
                                .extend(messages.into_iter().map(ChatEntry::from));
                        }
                        Err(e) => {
                            tracing::warn!("failed to load message history: {e}");
                        }
                    }
                }

                if app.crypto.has_session(target) {
                    app.status(&format!("chatting with {target} (E2EE active \u{1f512})"));
                } else {
                    app.crypto.add_pending(target);
                    let _ = outgoing_tx.send(ClientMessage::FetchPreKeyBundle {
                        target_user_id: uid.clone(),
                    });
                    app.status(&format!("fetching keys for {target}..."));
                }
                app.target_user = Some(uid.clone());
                app.peer_typing = None;
                app.last_typing_sent = None;
                flush_read_receipts(app, outgoing_tx, &uid);
            }
            Err(e) => {
                app.status(&format!("invalid username: {e}"));
            }
        }
        app.clear_input();
        return Ok(());
    }

    app.status(&format!("unknown command: {text}"));
    app.clear_input();
    Ok(())
}

fn handle_app_event(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    event: AppEvent,
) -> anyhow::Result<()> {
    match event {
        AppEvent::Connecting => app.status("connecting..."),
        AppEvent::Connected => app.status("connected, authenticating..."),
        AppEvent::Authenticated => app.status("authenticated \u{2713}"),
        AppEvent::AuthFailed(reason) => {
            app.status(&format!("auth failed: {reason}"));
        }
        AppEvent::Disconnected => {
            app.pending_msg_ids.clear();
            app.status("disconnected, reconnecting...");
        }
        AppEvent::Server(msg) => handle_server_message(app, outgoing_tx, msg)?,
    }
    Ok(())
}

#[allow(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]
fn handle_server_message(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    msg: ServerMessage,
) -> anyhow::Result<()> {
    match msg {
        ServerMessage::PreKeyBundleResponse { user_id, bundle } => {
            let peer = user_id.as_str().to_owned();
            if app.crypto.is_pending(&peer) {
                match app.crypto.init_session_from_bundle(&peer, &bundle) {
                    Ok(()) => {
                        app.status(&format!("E2EE session established with {peer} \u{1f512}"));
                    }
                    Err(e) => {
                        app.status(&format!("session init failed: {e}"));
                    }
                }
            }
        }
        ServerMessage::IncomingMessage(inbound) => {
            let sender_id = inbound.sender_id.clone();
            let (sender, msg_id, ok) = process_inbound(app, &inbound);
            if ok {
                let _ = outgoing_tx.send(ClientMessage::Ack {
                    message_ids: vec![inbound.message_id],
                });
                if app.target_user.is_none()
                    && let Ok(uid) = UserId::new(&sender)
                {
                    app.target_user = Some(uid);
                    app.status(&format!("now chatting with {sender}"));
                }
                if app
                    .target_user
                    .as_ref()
                    .is_some_and(|t| t.as_str() == sender)
                    && app.crypto.has_session(&sender)
                {
                    if let Ok(receipt_env) =
                        encrypt_read_receipt(&mut app.crypto, &sender, &[msg_id])
                    {
                        let _ = outgoing_tx.send(ClientMessage::SendReadReceipt {
                            recipient_id: sender_id,
                            envelope: receipt_env,
                        });
                    }
                } else {
                    accumulate_unread(app, sender, msg_id);
                }
            }
        }
        ServerMessage::QueuedMessages { messages } => {
            let mut ack_ids = Vec::with_capacity(messages.len());
            for inbound in &messages {
                let (sender, msg_id, ok) = process_inbound(app, inbound);
                if ok {
                    ack_ids.push(inbound.message_id.clone());
                    accumulate_unread(app, sender, msg_id);
                }
            }
            if !ack_ids.is_empty() {
                let _ = outgoing_tx.send(ClientMessage::Ack {
                    message_ids: ack_ids,
                });
            }
            if let Some(target) = app.target_user.clone() {
                flush_read_receipts(app, outgoing_tx, &target);
            }
        }
        ServerMessage::PeerTyping { sender_id } => {
            app.peer_typing = Some((sender_id.as_str().to_owned(), Instant::now()));
        }
        ServerMessage::MessageDelivered { message_ids } => {
            // Show ✓ only if we sent these messages (not for queued delivery receipts)
            if message_ids
                .iter()
                .any(|id| app.pending_msg_ids.contains(id))
            {
                app.pending_msg_ids.retain(|id| !message_ids.contains(id));
                app.status("  \u{2713}");
            }
        }
        ServerMessage::IncomingReadReceipt {
            sender_id,
            envelope,
        } => {
            // Decrypt the E2EE read receipt
            let sender = sender_id.as_str();
            if let Ok(plaintext) = app.crypto.decrypt(sender, &envelope)
                && let Ok(read_ids) = serde_json::from_slice::<Vec<String>>(&plaintext)
                && !read_ids.is_empty()
            {
                app.status("  \u{2713}\u{2713}");
            }
        }
        ServerMessage::PreKeyLow { remaining } => {
            app.status(&format!("warning: only {remaining} pre-keys remaining"));
        }
        ServerMessage::Error { message, .. } => {
            app.status(&format!("server error: {message}"));
        }
        _ => {}
    }
    Ok(())
}

/// Decrypt an inbound message and push to chat history.
fn process_inbound(app: &mut App, inbound: &protocol::InboundMessage) -> (String, MessageId, bool) {
    let sender = inbound.sender_id.as_str().to_owned();
    let (text, ok) = app.crypto.decrypt_to_text(&sender, &inbound.envelope);
    if ok
        && let Some(ref conn) = app.db
        && let Err(e) = crate::db::insert_message(
            conn,
            &sender,
            crate::db::MessageDirection::Received,
            &inbound.message_id.to_string(),
            &text,
        )
    {
        tracing::warn!("failed to persist received message: {e}");
    }
    app.chat_history.push(ChatEntry::Received {
        sender: sender.clone(),
        text,
    });
    (sender, inbound.message_id.clone(), ok)
}

/// Try to flush pending read receipts for `target` — encrypt, send, remove from unread map.
fn flush_read_receipts(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    target: &UserId,
) {
    let target_str = target.as_str();
    if let Some(unread) = app.unread_messages.get(target_str)
        && !unread.is_empty()
        && app.crypto.has_session(target_str)
        && let Ok(receipt_env) = encrypt_read_receipt(&mut app.crypto, target_str, unread)
    {
        let _ = outgoing_tx.send(ClientMessage::SendReadReceipt {
            recipient_id: target.clone(),
            envelope: receipt_env,
        });
        app.unread_messages.remove(target_str);
    }
}

/// Push a message ID to the bounded unread list for a peer.
fn accumulate_unread(app: &mut App, sender: String, msg_id: MessageId) {
    let entry = app.unread_messages.entry(sender).or_default();
    if entry.len() < consts::MAX_RECEIPT_BATCH {
        entry.push(msg_id);
    }
}

/// Encrypt a read receipt (list of message ID strings) using the E2EE session.
fn encrypt_read_receipt(
    crypto: &mut CryptoManager,
    peer_id: &str,
    message_ids: &[MessageId],
) -> Result<protocol::EncryptedEnvelope, crate::crypto_mgr::CryptoError> {
    // Cap batch to prevent oversized envelopes
    let capped = if message_ids.len() > consts::MAX_RECEIPT_BATCH {
        &message_ids[..consts::MAX_RECEIPT_BATCH]
    } else {
        message_ids
    };
    let id_strings: Vec<String> = capped.iter().map(ToString::to_string).collect();
    let plaintext = serde_json::to_vec(&id_strings)
        .map_err(|_| crate::crypto_mgr::CryptoError::RatchetFailed)?;
    // Check plaintext size before encrypting to avoid ratchet desync
    let estimated_ct_len = (plaintext.len() + 18) / 3 * 4;
    if estimated_ct_len > consts::MAX_CIPHERTEXT_BYTES {
        return Err(crate::crypto_mgr::CryptoError::RatchetFailed);
    }
    crypto.encrypt(peer_id, &plaintext)
}

async fn register_with_server(
    user_id: &str,
    server_url: &str,
    crypto: &mut CryptoManager,
) -> anyhow::Result<()> {
    let identity = crypto.identity();
    let (ws, _) = connect_async(server_url).await?;
    let (mut sink, mut stream) = futures::StreamExt::split(ws);

    let spk = crypto::keys::SignedPreKey::generate(0, identity);
    let opks = crypto::keys::generate_one_time_prekeys(0, 100)?;

    let bundle = protocol::PreKeyBundle {
        identity_key: B64.encode(identity.verifying_key().as_bytes()),
        signed_prekey: B64.encode(spk.public().as_bytes()),
        signed_prekey_id: spk.key_id(),
        signed_prekey_signature: B64.encode(spk.signature().to_bytes()),
        one_time_prekey: None,
    };

    let otk_uploads: Vec<protocol::OneTimePreKey> = opks
        .iter()
        .map(|k| protocol::OneTimePreKey {
            key_id: k.key_id(),
            public_key: B64.encode(k.public().as_bytes()),
        })
        .collect();

    let uid = UserId::new(user_id)?;
    let register = ClientMessage::Register {
        user_id: uid,
        bundle,
        one_time_prekeys: otk_uploads,
    };

    let json = serde_json::to_string(&register)?;
    futures::SinkExt::send(
        &mut sink,
        tokio_tungstenite::tungstenite::Message::Text(json.into()),
    )
    .await?;

    let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) =
        futures::StreamExt::next(&mut stream).await
    else {
        anyhow::bail!("no response from server during registration");
    };

    if matches!(serde_json::from_str(&text), Ok(ServerMessage::AuthSuccess)) {
        // Persist SPK/OPK private keys for future X3DH as Bob
        crypto.persist_registration_keys(&spk, &opks)?;
        return Ok(());
    }
    if let Ok(ServerMessage::AuthFailure { reason }) = serde_json::from_str(&text) {
        // "already exists" on first launch means someone else owns this username.
        // Don't silently succeed — the user needs to pick a different name.
        anyhow::bail!("registration rejected: {reason}");
    }
    anyhow::bail!("unexpected server response during registration");
}

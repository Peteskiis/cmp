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

struct App {
    input: String,
    cursor_pos: usize,
    input_scroll: usize,
    target_user: Option<UserId>,
    running: bool,
    crypto: CryptoManager,
    /// Typing indicator debounce.
    last_typing_sent: Option<Instant>,
    /// Peer typing state with expiry timestamp.
    peer_typing: Option<(String, Instant)>,
    /// Track delivery/read status for sent messages.
    sent_status: HashMap<MessageId, MessageStatus>,
    /// Messages displayed but not read-receipted (chat target didn't match sender).
    unread_messages: HashMap<String, Vec<MessageId>>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MessageStatus {
    Sent,
    Delivered,
    #[allow(dead_code)] // Entries are evicted on Read, but variant documents the lifecycle
    Read,
}

impl App {
    fn new(crypto: CryptoManager) -> Self {
        Self {
            input: String::new(),
            cursor_pos: 0,
            input_scroll: 0,
            target_user: None,
            running: true,
            crypto,
            last_typing_sent: None,
            peer_typing: None,
            sent_status: HashMap::new(),
            unread_messages: HashMap::new(),
        }
    }

    fn clear_input(&mut self) {
        self.input.clear();
        self.cursor_pos = 0;
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

    let (mut terminal, _guard) = ui::init()?;
    ui::insert_status(&mut terminal, &format!("logged in as {user_id}"))?;
    ui::insert_status(&mut terminal, "type /help for commands")?;

    let mut app = App::new(crypto);
    let mut event_stream = EventStream::new();

    while app.running {
        let term_width = terminal.size()?.width as usize;
        let max_visible = term_width.saturating_sub(4);
        update_scroll(&mut app, max_visible);
        let visible_input = visible_slice(&app.input, app.input_scroll, max_visible);
        let visible_cursor = app.cursor_pos.saturating_sub(app.input_scroll);

        // Show typing indicator if peer is typing and hasn't timed out
        let typing_label = app
            .peer_typing
            .as_ref()
            .filter(|(_, ts)| ts.elapsed() < Duration::from_secs(5))
            .map(|(name, _)| name.as_str());
        ui::draw_input(&mut terminal, &visible_input, visible_cursor, typing_label)?;

        // Only tick when someone is typing — avoids idle redraws
        let typing_tick = async {
            if app.peer_typing.is_some() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            Some(Ok(event)) = event_stream.next() => {
                handle_key_event(&mut app, &mut terminal, &outgoing_tx, event)?;
            }
            Some(event) = event_rx.recv() => {
                handle_app_event(&mut app, &mut terminal, &outgoing_tx, event)?;
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

fn dirs_data_dir(user_id: &str) -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    std::path::PathBuf::from(home).join(".cmp").join(user_id)
}

const fn update_scroll(app: &mut App, max_visible: usize) {
    if max_visible == 0 {
        return;
    }
    if app.cursor_pos < app.input_scroll {
        app.input_scroll = app.cursor_pos;
    } else if app.cursor_pos >= app.input_scroll + max_visible {
        app.input_scroll = app.cursor_pos - max_visible + 1;
    }
}

fn visible_slice(input: &str, scroll: usize, max_len: usize) -> String {
    input.chars().skip(scroll).take(max_len).collect()
}

#[allow(clippy::cognitive_complexity, clippy::needless_pass_by_value)]
fn handle_key_event(
    app: &mut App,
    terminal: &mut ui::Term,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    event: Event,
) -> anyhow::Result<()> {
    let Event::Key(key) = event else {
        return Ok(());
    };

    match (key.code, key.modifiers) {
        (KeyCode::Char('d' | 'c'), KeyModifiers::CONTROL) => {
            app.running = false;
        }
        (KeyCode::Enter, _) => {
            handle_enter(app, terminal, outgoing_tx)?;
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
        (KeyCode::Char(c), mods) if mods.is_empty() || mods == KeyModifiers::SHIFT => {
            let byte_pos = app
                .input
                .char_indices()
                .nth(app.cursor_pos)
                .map_or(app.input.len(), |(i, _)| i);
            app.input.insert(byte_pos, c);
            app.cursor_pos += 1;

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
    terminal: &mut ui::Term,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
) -> anyhow::Result<()> {
    let text = app.input.trim().to_owned();
    if text.is_empty() {
        return Ok(());
    }

    // Slash commands
    if text.starts_with('/') {
        return handle_command(app, terminal, outgoing_tx, &text);
    }

    let Some(ref target) = app.target_user else {
        ui::insert_status(terminal, "use /chat <username> first")?;
        app.clear_input();
        return Ok(());
    };
    let target_str = target.as_str();

    if !app.crypto.has_session(target_str) {
        ui::insert_status(terminal, "waiting for session establishment...")?;
        app.clear_input();
        return Ok(());
    }

    // Check plaintext size BEFORE encrypting to avoid ratchet desync
    let estimated_b64_len = (text.len() + 18) / 3 * 4;
    if estimated_b64_len > consts::MAX_CIPHERTEXT_BYTES {
        ui::insert_status(terminal, "message too long")?;
        app.clear_input();
        return Ok(());
    }

    let envelope = match app.crypto.encrypt(target_str, text.as_bytes()) {
        Ok(env) => env,
        Err(e) => {
            ui::insert_status(terminal, &format!("encrypt error: {e}"))?;
            app.clear_input();
            return Ok(());
        }
    };

    let msg_id = MessageId::new();
    // Cap sent_status to prevent unbounded growth from unreceipted messages
    if app.sent_status.len() >= 10_000 {
        app.sent_status.clear();
    }
    app.sent_status.insert(msg_id.clone(), MessageStatus::Sent);
    let _ = outgoing_tx.send(ClientMessage::SendMessage {
        recipient_id: target.clone(),
        message_id: msg_id,
        envelope,
    });
    ui::insert_user_message(terminal, &text)?;
    app.clear_input();
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
fn handle_command(
    app: &mut App,
    terminal: &mut ui::Term,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    text: &str,
) -> anyhow::Result<()> {
    if text == "/contacts" || text == "/c" {
        let peers = app.crypto.session_peers();
        if peers.is_empty() {
            ui::insert_status(terminal, "no contacts yet")?;
        } else {
            ui::insert_status(terminal, &format!("contacts ({})", peers.len()))?;
            for peer in &peers {
                let active = app
                    .target_user
                    .as_ref()
                    .is_some_and(|t| t.as_str() == *peer);
                let marker = if active { " \u{25c0}" } else { "" };
                ui::insert_status(terminal, &format!("  {peer}{marker}"))?;
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
        ui::insert_status(terminal, "commands:")?;
        ui::insert_status(
            terminal,
            "  /chat <user>  \u{2014} start or switch conversation",
        )?;
        ui::insert_status(terminal, "  /contacts     \u{2014} list all contacts")?;
        ui::insert_status(terminal, "  /quit         \u{2014} exit")?;
        ui::insert_status(terminal, "  /help         \u{2014} show this help")?;
        app.clear_input();
        return Ok(());
    }

    if text == "/chat" {
        ui::insert_status(terminal, "usage: /chat <username>")?;
        app.clear_input();
        return Ok(());
    }

    if let Some(target) = text.strip_prefix("/chat ") {
        let target = target.trim();
        match UserId::new(target) {
            Ok(uid) => {
                if app.crypto.has_session(target) {
                    ui::insert_status(
                        terminal,
                        &format!("chatting with {target} (E2EE active \u{1f512})"),
                    )?;
                } else {
                    app.crypto.add_pending(target);
                    let _ = outgoing_tx.send(ClientMessage::FetchPreKeyBundle {
                        target_user_id: uid.clone(),
                    });
                    ui::insert_status(terminal, &format!("fetching keys for {target}..."))?;
                }
                app.target_user = Some(uid.clone());
                app.peer_typing = None;
                app.last_typing_sent = None;
                // Flush pending read receipts — only remove from map if encrypt succeeds
                if let Some(unread) = app.unread_messages.get(target)
                    && !unread.is_empty()
                    && app.crypto.has_session(target)
                    && let Ok(receipt_env) = encrypt_read_receipt(&mut app.crypto, target, unread)
                {
                    let _ = outgoing_tx.send(ClientMessage::SendReadReceipt {
                        recipient_id: uid,
                        envelope: receipt_env,
                    });
                    app.unread_messages.remove(target);
                }
            }
            Err(e) => {
                ui::insert_status(terminal, &format!("invalid username: {e}"))?;
            }
        }
        app.clear_input();
        return Ok(());
    }

    ui::insert_status(terminal, &format!("unknown command: {text}"))?;
    app.clear_input();
    Ok(())
}

fn handle_app_event(
    app: &mut App,
    terminal: &mut ui::Term,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    event: AppEvent,
) -> anyhow::Result<()> {
    match event {
        AppEvent::Connecting => ui::insert_status(terminal, "connecting...")?,
        AppEvent::Connected => ui::insert_status(terminal, "connected, authenticating...")?,
        AppEvent::Authenticated => ui::insert_status(terminal, "authenticated \u{2713}")?,
        AppEvent::AuthFailed(reason) => {
            ui::insert_status(terminal, &format!("auth failed: {reason}"))?;
        }
        AppEvent::Disconnected => ui::insert_status(terminal, "disconnected, reconnecting...")?,
        AppEvent::Server(msg) => handle_server_message(app, terminal, outgoing_tx, msg)?,
    }
    Ok(())
}

#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
fn handle_server_message(
    app: &mut App,
    terminal: &mut ui::Term,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    msg: ServerMessage,
) -> anyhow::Result<()> {
    match msg {
        ServerMessage::PreKeyBundleResponse { user_id, bundle } => {
            let peer = user_id.as_str().to_owned();
            if app.crypto.is_pending(&peer) {
                match app.crypto.init_session_from_bundle(&peer, &bundle) {
                    Ok(()) => {
                        ui::insert_status(
                            terminal,
                            &format!("E2EE session established with {peer} \u{1f512}"),
                        )?;
                    }
                    Err(e) => {
                        ui::insert_status(terminal, &format!("session init failed: {e}"))?;
                    }
                }
            }
        }
        ServerMessage::IncomingMessage(inbound) => {
            let sender = inbound.sender_id.as_str().to_owned();
            let (text, ok) = app.crypto.decrypt_to_text(&sender, &inbound.envelope);
            ui::insert_friend_message(terminal, &sender, &text)?;
            if ok {
                let msg_id = inbound.message_id.clone();
                let _ = outgoing_tx.send(ClientMessage::Ack {
                    message_ids: vec![inbound.message_id],
                });
                // Auto-set chat target so Bob can reply without /chat
                if app.target_user.is_none()
                    && let Ok(uid) = UserId::new(&sender)
                {
                    app.target_user = Some(uid);
                    ui::insert_status(terminal, &format!("now chatting with {sender}"))?;
                }
                // Read receipt: if chat target matches sender, mark as read immediately
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
                            recipient_id: inbound.sender_id,
                            envelope: receipt_env,
                        });
                    }
                } else {
                    let entry = app.unread_messages.entry(sender).or_default();
                    if entry.len() < consts::MAX_RECEIPT_BATCH {
                        entry.push(msg_id);
                    }
                }
            }
        }
        ServerMessage::QueuedMessages { messages } => {
            let mut ack_ids = Vec::with_capacity(messages.len());
            for inbound in messages {
                let sender = inbound.sender_id.as_str().to_owned();
                let (text, ok) = app.crypto.decrypt_to_text(&sender, &inbound.envelope);
                ui::insert_friend_message(terminal, &sender, &text)?;
                if ok {
                    ack_ids.push(inbound.message_id.clone());
                    let entry = app.unread_messages.entry(sender).or_default();
                    if entry.len() < consts::MAX_RECEIPT_BATCH {
                        entry.push(inbound.message_id);
                    }
                }
            }
            if !ack_ids.is_empty() {
                let _ = outgoing_tx.send(ClientMessage::Ack {
                    message_ids: ack_ids,
                });
            }
            // Flush read receipts for messages from the current chat target
            if let Some(ref target) = app.target_user {
                let target_str = target.as_str();
                if let Some(unread) = app.unread_messages.get(target_str)
                    && !unread.is_empty()
                    && app.crypto.has_session(target_str)
                    && let Ok(receipt_env) =
                        encrypt_read_receipt(&mut app.crypto, target_str, unread)
                {
                    let _ = outgoing_tx.send(ClientMessage::SendReadReceipt {
                        recipient_id: target.clone(),
                        envelope: receipt_env,
                    });
                    app.unread_messages.remove(target_str);
                }
            }
        }
        ServerMessage::PeerTyping { sender_id } => {
            app.peer_typing = Some((sender_id.as_str().to_owned(), Instant::now()));
        }
        ServerMessage::MessageSent { message_id } => {
            app.sent_status
                .entry(message_id)
                .or_insert(MessageStatus::Sent);
            ui::insert_status(terminal, "  \u{2713} sent")?;
        }
        ServerMessage::MessageDelivered { message_ids } => {
            for id in &message_ids {
                if let Some(status) = app.sent_status.get_mut(id)
                    && *status < MessageStatus::Delivered
                {
                    *status = MessageStatus::Delivered;
                }
            }
            ui::insert_status(terminal, "  \u{2713}\u{2713} delivered")?;
        }
        ServerMessage::IncomingReadReceipt {
            sender_id,
            envelope,
        } => {
            // Decrypt the E2EE read receipt
            let sender = sender_id.as_str();
            if let Ok(plaintext) = app.crypto.decrypt(sender, &envelope)
                && let Ok(read_ids) = serde_json::from_slice::<Vec<String>>(&plaintext)
            {
                let mut any_read = false;
                for id_str in &read_ids {
                    if let Ok(uuid) = uuid::Uuid::parse_str(id_str) {
                        let mid = MessageId::from(uuid);
                        // Evict on Read — entry is dead weight after this
                        app.sent_status.remove(&mid);
                        any_read = true;
                    }
                }
                if any_read {
                    ui::insert_status(terminal, "  \u{1f441} read")?;
                }
            }
        }
        ServerMessage::PreKeyLow { remaining } => {
            ui::insert_status(
                terminal,
                &format!("warning: only {remaining} pre-keys remaining"),
            )?;
        }
        ServerMessage::Error { message, .. } => {
            ui::insert_status(terminal, &format!("server error: {message}"))?;
        }
        _ => {}
    }
    Ok(())
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

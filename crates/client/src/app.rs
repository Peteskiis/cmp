use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crossterm::event::EventStream;
use futures::StreamExt;
use protocol::{ClientMessage, MessageId, ServerMessage, UserId, consts};
use tokio::sync::mpsc;

use crate::command_popup::CommandPopup;
use crate::crypto_mgr::{CryptoManager, InboundDecrypt};

#[path = "app_inbound.rs"]
mod inbound;
#[path = "app_prekeys.rs"]
mod prekeys;
use crate::status_bar::{ConnectionStatus, StatusBar};
use crate::{net, ui};
use inbound::{
    accumulate_unread, flush_read_receipts, process_inbound, queue_ack, queue_read_receipt_ack,
};

/// Events that flow into the main UI loop.
pub(crate) enum AppEvent {
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
    Tip(String),
    Warning(String),
}

pub(crate) struct App {
    pub(crate) user_id: UserId,
    pub(crate) input: String,
    pub(crate) cursor_pos: usize,
    pub(crate) input_scroll: usize,
    pub(crate) target_user: Option<UserId>,
    pub(crate) running: bool,
    pub(crate) authenticated: bool,
    pub(crate) crypto: CryptoManager,
    pub(crate) last_typing_sent: Option<Instant>,
    pub(crate) status_bar: StatusBar,
    pub(crate) pending_msg_ids: Vec<MessageId>,
    pub(crate) unread_messages: HashMap<String, Vec<MessageId>>,
    pub(crate) chat_history: Vec<ChatEntry>,
    pub(crate) db: Option<rusqlite::Connection>,
    pub(crate) command_popup: Option<CommandPopup>,
    /// Previously sent messages for up/down arrow recall.
    pub(crate) input_history: VecDeque<String>,
    /// Current position in input history (`None` = editing fresh input).
    pub(crate) history_index: Option<usize>,
    /// Saved draft when browsing history, restored on down-past-end.
    pub(crate) history_draft: String,
}

impl App {
    pub(crate) fn new(
        user_id: UserId,
        crypto: CryptoManager,
        db: Option<rusqlite::Connection>,
    ) -> Self {
        Self {
            user_id,
            input: String::new(),
            cursor_pos: 0,
            input_scroll: 0,
            target_user: None,
            running: true,
            authenticated: false,
            crypto,
            last_typing_sent: None,
            status_bar: StatusBar::new(),
            pending_msg_ids: Vec::new(),
            unread_messages: HashMap::new(),
            chat_history: Vec::new(),
            db,
            command_popup: None,
            input_history: VecDeque::new(),
            history_index: None,
            history_draft: String::new(),
        }
    }

    pub(crate) fn status(&mut self, text: &str) {
        self.chat_history.push(ChatEntry::Status(text.to_owned()));
    }

    pub(crate) const MAX_INPUT_HISTORY: usize = 500;

    pub(crate) fn clear_input(&mut self) {
        self.save_to_history();
        self.reset_input();
    }

    pub(crate) fn discard_input(&mut self) {
        self.reset_input();
    }

    fn save_to_history(&mut self) {
        let trimmed = self.input.trim();
        if !trimmed.is_empty() && self.input_history.back().is_none_or(|last| last != trimmed) {
            if self.input_history.len() >= Self::MAX_INPUT_HISTORY {
                self.input_history.pop_front();
            }
            self.input_history.push_back(trimmed.to_owned());
        }
    }

    fn reset_input(&mut self) {
        self.input.clear();
        self.cursor_pos = 0;
        self.input_scroll = 0;
        self.history_index = None;
        self.history_draft.clear();
    }

    pub(crate) fn sync_command_popup(&mut self) {
        if self.input.starts_with('/') {
            let popup = self.command_popup.get_or_insert_with(CommandPopup::new);
            if !popup.sync(&self.input) {
                self.command_popup = None;
            }
        } else {
            self.command_popup = None;
        }
    }

    pub(crate) fn insert_at_cursor(&mut self, ch: char) {
        let byte_pos = self
            .input
            .char_indices()
            .nth(self.cursor_pos)
            .map_or(self.input.len(), |(i, _)| i);
        self.input.insert(byte_pos, ch);
        self.cursor_pos += 1;
    }

    fn load_chat_history(&mut self, peer_id: &str) {
        self.chat_history.clear();
        if let Some(ref conn) = self.db {
            match crate::db::load_recent_messages(conn, peer_id) {
                Ok(messages) => {
                    self.chat_history
                        .extend(messages.into_iter().map(ChatEntry::from));
                }
                Err(e) => {
                    tracing::warn!("failed to load message history: {e}");
                }
            }
        }
    }

    fn persist_message(
        &self,
        peer_id: &str,
        direction: crate::db::MessageDirection,
        msg_id: &str,
        body: &str,
    ) -> anyhow::Result<bool> {
        let conn = self
            .db
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("message database unavailable"))?;
        crate::db::insert_message(conn, peer_id, direction, msg_id, body)
    }
}

#[allow(clippy::cognitive_complexity)]
pub(crate) async fn run(user_id: &str, server_url: &str) -> anyhow::Result<()> {
    let validated_uid = UserId::new(user_id)?;

    let data_dir = dirs_data_dir(user_id);
    let mut crypto = CryptoManager::load_or_generate(&data_dir)?;

    if crypto.needs_registration() {
        match net::register_with_server(user_id, server_url, &mut crypto).await {
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
    let mut app = App::new(validated_uid, crypto, db);
    if app.db.is_none() {
        app.status("warning: message history unavailable");
    }
    app.chat_history
        .push(ChatEntry::Tip("Tip: type / for commands".to_owned()));
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

        ui::draw_input(
            &mut terminal,
            &app.chat_history,
            &visual_lines,
            cursor_row,
            cursor_col,
            app.input_scroll,
            &app.status_bar,
            app.command_popup.as_ref(),
        )?;

        let status_tick = async {
            if app.status_bar.needs_tick() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            Some(Ok(event)) = event_stream.next() => {
                crate::input::handle_key_event(&mut app, &terminal, &outgoing_tx, event)?;
            }
            Some(event) = event_rx.recv() => {
                handle_app_event(&mut app, &outgoing_tx, event)?;
            }
            () = status_tick => {
                app.status_bar.tick();
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

#[allow(clippy::cognitive_complexity)]
pub(crate) fn handle_enter(
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

    let Some(target) = app.target_user.clone() else {
        app.status("use /chat <username> first");
        app.clear_input();
        return Ok(());
    };
    let target_str = target.as_str();

    // Note to self: skip crypto and server, just store locally
    if target_str == app.user_id.as_str() {
        let msg_id = MessageId::new();
        if let Err(error) = app.persist_message(
            target_str,
            crate::db::MessageDirection::Sent,
            &msg_id.to_string(),
            &text,
        ) {
            tracing::warn!("failed to persist note: {error}");
        }
        app.chat_history.push(ChatEntry::Sent(text));
        app.clear_input();
        return Ok(());
    }

    if !app.crypto.has_session(target_str) {
        app.status("waiting for session establishment...");
        app.clear_input();
        return Ok(());
    }
    if !app.authenticated {
        app.status("waiting for server connection...");
        return Ok(());
    }
    if prekeys::refresh_expired_session(app, outgoing_tx, &target) {
        return Ok(());
    }

    // Check plaintext size BEFORE encrypting to avoid ratchet desync
    let estimated_b64_len = (text.len() + 18) / 3 * 4;
    if estimated_b64_len > consts::MAX_CIPHERTEXT_BYTES {
        app.status("message too long");
        app.clear_input();
        return Ok(());
    }

    let msg_id = MessageId::new();
    let outbound = match app
        .crypto
        .encrypt_message(target_str, &target, &msg_id, text.as_bytes())
    {
        Ok(message) => message,
        Err(e) => {
            app.status(&format!("encrypt error: {e}"));
            app.clear_input();
            return Ok(());
        }
    };

    // Cap pending IDs to prevent unbounded growth
    if app.pending_msg_ids.len() >= 10_000 {
        app.pending_msg_ids.clear();
    }
    app.pending_msg_ids.push(msg_id.clone());
    let _ = outgoing_tx.send(outbound);
    if let Err(error) = app.persist_message(
        target_str,
        crate::db::MessageDirection::Sent,
        &msg_id.to_string(),
        &text,
    ) {
        tracing::warn!("failed to persist sent message: {error}");
    }
    app.chat_history.push(ChatEntry::Sent(text));
    app.clear_input();
    Ok(())
}

#[allow(
    clippy::cognitive_complexity,
    clippy::unnecessary_wraps,
    clippy::too_many_lines
)]
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
                let verified = app
                    .db
                    .as_ref()
                    .and_then(|c| crate::db::get_verification(c, peer))
                    .is_some();
                let badge = if verified { " \u{2705}" } else { "" };
                let arrow = if active { " \u{25c0}" } else { "" };
                app.status(&format!("  {peer}{badge}{arrow}"));
            }
        }
        app.clear_input();
        return Ok(());
    }

    if text == "/notes" || text == "/notetoself" {
        let self_id = app.user_id.clone();
        app.load_chat_history(self_id.as_str());
        app.target_user = Some(self_id);
        app.status("note to self \u{1f4dd}");
        app.clear_input();
        return Ok(());
    }

    let verify_cmd = match text {
        "/v" | "/verify" => Some("/verify"),
        "/v confirm" | "/verify confirm" => Some("/verify confirm"),
        "/v clear" | "/verify clear" => Some("/verify clear"),
        _ => None,
    };
    if let Some(cmd) = verify_cmd {
        handle_verify(app, cmd);
        app.clear_input();
        return Ok(());
    }

    if text == "/keys" || text == "/k" {
        crate::input::show_keybindings(app);
        app.clear_input();
        return Ok(());
    }

    if text == "/quit" || text == "/q" {
        app.running = false;
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
                app.load_chat_history(target);

                if target == app.user_id.as_str() {
                    app.target_user = Some(uid);
                    app.status("note to self \u{1f4dd}");
                } else if app.crypto.has_session(target) {
                    app.status(&format!("chatting with {target} (E2EE active \u{1f512})"));
                    app.target_user = Some(uid.clone());
                    app.status_bar.clear_typing();
                    app.last_typing_sent = None;
                    flush_read_receipts(app, outgoing_tx, &uid);
                } else {
                    app.crypto.add_pending(target);
                    if !app.authenticated {
                        app.status("waiting for server connection...");
                        app.target_user = Some(uid);
                        app.clear_input();
                        return Ok(());
                    }
                    let _ = outgoing_tx.send(ClientMessage::FetchPreKeyBundle {
                        target_user_id: uid.clone(),
                    });
                    app.status(&format!("fetching keys for {target}..."));
                    app.target_user = Some(uid.clone());
                    app.status_bar.clear_typing();
                    app.last_typing_sent = None;
                }
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
        AppEvent::Connecting => {
            app.status_bar.set_connection(ConnectionStatus::Connecting);
        }
        AppEvent::Connected => {
            app.status_bar
                .set_connection(ConnectionStatus::Authenticating);
        }
        AppEvent::Authenticated => {
            app.authenticated = true;
            app.status_bar
                .set_connection(ConnectionStatus::Authenticated(Instant::now()));
            for pending in app.crypto.pending_messages() {
                let _ = outgoing_tx.send(pending);
            }
            for peer in app.crypto.pending_peers() {
                if let Ok(target_user_id) = UserId::new(&peer) {
                    let _ = outgoing_tx.send(ClientMessage::FetchPreKeyBundle { target_user_id });
                }
            }
        }
        AppEvent::AuthFailed(reason) => {
            app.authenticated = false;
            app.status_bar
                .set_connection(ConnectionStatus::AuthFailed(reason));
        }
        AppEvent::Disconnected => {
            app.authenticated = false;
            app.pending_msg_ids.clear();
            app.status_bar
                .set_connection(ConnectionStatus::Disconnected);
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
                        // TOFU: store the peer's identity key from the SPK-verified
                        // bundle. Unlike the receiver path (process_inbound), the
                        // initiator has no AEAD proof yet — safety numbers let the
                        // user verify OOB. This matches Signal's initiator behavior.
                        track_peer_identity(app, &peer, &bundle.identity_key);
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
            let (sender, msg_id, should_ack, fresh) = process_inbound(app, &inbound);
            if should_ack {
                queue_ack(app, outgoing_tx, vec![inbound.message_id]);
            }
            if fresh {
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
                    if let Ok(receipt) = app.crypto.encrypt_read_receipt(
                        &sender,
                        &sender_id,
                        std::slice::from_ref(&msg_id),
                    ) {
                        let _ = outgoing_tx.send(receipt);
                    } else {
                        accumulate_unread(app, sender, msg_id);
                    }
                } else {
                    accumulate_unread(app, sender, msg_id);
                }
            }
        }
        ServerMessage::QueuedMessages { messages } => {
            let mut ack_ids = Vec::with_capacity(messages.len());
            for inbound in &messages {
                let (sender, msg_id, should_ack, fresh) = process_inbound(app, inbound);
                if should_ack {
                    ack_ids.push(inbound.message_id.clone());
                }
                if fresh {
                    accumulate_unread(app, sender, msg_id);
                }
            }
            if !ack_ids.is_empty() {
                queue_ack(app, outgoing_tx, ack_ids);
            }
            if let Some(target) = app.target_user.clone() {
                flush_read_receipts(app, outgoing_tx, &target);
            }
        }
        ServerMessage::PeerTyping { sender_id } => {
            app.status_bar.set_typing(sender_id.as_str().to_owned());
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
        ServerMessage::MessageSent { message_id } => {
            if let Err(error) = app.crypto.confirm_message_sent(&message_id) {
                tracing::warn!("failed to confirm durable outbound message: {error}");
            } else {
                let _ = outgoing_tx.send(ClientMessage::AckMessageSent {
                    message_ids: vec![message_id],
                });
            }
        }
        ServerMessage::MessageRejected { message_id, reason } => {
            prekeys::handle_message_rejected(app, outgoing_tx, &message_id);
            app.pending_msg_ids.retain(|id| id != &message_id);
            app.status(&format!("message rejected; refreshing session: {reason}"));
        }
        ServerMessage::AckSuccess {
            ack_id,
            message_ids,
        } => {
            if let Err(error) = app.crypto.confirm_acked(&ack_id, &message_ids) {
                tracing::warn!("failed to confirm durable acknowledgements: {error}");
            }
        }
        ServerMessage::ReadReceiptSent { receipt_id } => {
            if let Err(error) = app.crypto.confirm_read_receipt_sent(&receipt_id) {
                tracing::warn!("failed to confirm durable read receipt: {error}");
            } else {
                let _ = outgoing_tx.send(ClientMessage::AckReadReceiptSent {
                    receipt_ids: vec![receipt_id],
                });
            }
        }
        ServerMessage::IncomingReadReceipt {
            sender_id,
            receipt_id,
            envelope,
        } => {
            let sender = sender_id.as_str();
            match app
                .crypto
                .decrypt_message_to_text(sender, &receipt_id, &envelope)
            {
                InboundDecrypt::Pending(text) => {
                    if serde_json::from_str::<Vec<String>>(&text).is_ok() {
                        app.status("  \u{2713}\u{2713}");
                        let _ = app.crypto.confirm_inbound_stored(sender, &receipt_id);
                        queue_read_receipt_ack(app, outgoing_tx, vec![receipt_id]);
                    }
                }
                InboundDecrypt::Duplicate => {
                    queue_read_receipt_ack(app, outgoing_tx, vec![receipt_id]);
                }
                InboundDecrypt::Failed => {}
            }
        }
        ServerMessage::PreKeyLow { remaining } => match app.crypto.queue_prekey_replenishment() {
            Ok(upload) => {
                let _ = outgoing_tx.send(upload);
                app.status(&format!(
                    "replenishing one-time pre-keys ({remaining} remaining)"
                ));
            }
            Err(error) => {
                app.status(&format!("pre-key replenishment failed: {error}"));
            }
        },
        ServerMessage::PreKeysUploaded {
            upload_id,
            accepted,
            remaining,
        } => {
            match app
                .crypto
                .confirm_prekeys_uploaded(&upload_id, accepted, remaining)
            {
                Ok(replacement) => {
                    if let Some(upload) = replacement {
                        let _ = outgoing_tx.send(upload);
                    }
                    if accepted {
                        app.status(&format!(
                            "one-time pre-keys replenished ({remaining} available)"
                        ));
                    } else {
                        app.status(&format!(
                            "pre-key upload rejected ({remaining} already available)"
                        ));
                    }
                }
                Err(error) => {
                    tracing::warn!("failed to confirm durable pre-key upload: {error}");
                }
            }
        }
        ServerMessage::Error { message, .. } => {
            app.status(&format!("server error: {message}"));
        }
        _ => {}
    }
    Ok(())
}

fn handle_verify(app: &mut App, text: &str) {
    let Some(ref target) = app.target_user else {
        app.status("use /chat <username> first");
        return;
    };
    let key = app.crypto.local_identity_key_b64();
    let uid = app.user_id.as_str();
    let entries =
        crate::verification::handle_command(uid, &key, target.as_str(), text, app.db.as_ref());
    app.chat_history.extend(entries);
}

/// Store a peer's identity key (from a `PreKey` header) and warn if it changed.
fn track_peer_identity(app: &mut App, peer_id: &str, identity_key_b64: &str) {
    if let Some(ref conn) = app.db
        && let Some(warning) =
            crate::verification::check_peer_identity(conn, peer_id, identity_key_b64)
    {
        app.chat_history.push(ChatEntry::Warning(warning));
    }
}

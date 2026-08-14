use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crossterm::event::EventStream;
use futures::StreamExt;
use protocol::{ClientMessage, MessageId, ServerMessage, UserId, consts};
use tokio::sync::mpsc;
use tui_textarea::{TextArea, WrapMode};

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
    Warning(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Focus {
    Conversations,
    #[default]
    Composer,
}

pub(crate) enum Modal {
    NewChat(Box<TextArea<'static>>),
    Help,
    Verification(Vec<ChatEntry>),
}

pub(crate) struct Notice {
    text: String,
    created_at: Instant,
}

pub(crate) struct App {
    pub(crate) user_id: UserId,
    pub(crate) composer: TextArea<'static>,
    pub(crate) target_user: Option<UserId>,
    pub(crate) running: bool,
    pub(crate) authenticated: bool,
    pub(crate) crypto: CryptoManager,
    pub(crate) last_typing_sent: Option<Instant>,
    pub(crate) status_bar: StatusBar,
    pub(crate) pending_msg_ids: Vec<MessageId>,
    pub(crate) unread_messages: HashMap<String, Vec<MessageId>>,
    pub(crate) identity_warnings: HashMap<String, String>,
    pub(crate) chat_history: Vec<ChatEntry>,
    pub(crate) db: Option<rusqlite::Connection>,
    pub(crate) focus: Focus,
    pub(crate) modal: Option<Modal>,
    pub(crate) selected_conversation: Option<String>,
    /// Number of rendered rows above the newest message.
    pub(crate) message_scroll: usize,
    pub(crate) last_rendered_max_scroll: Option<usize>,
    pub(crate) notice: Option<Notice>,
}

impl App {
    pub(crate) fn new(
        user_id: UserId,
        crypto: CryptoManager,
        db: Option<rusqlite::Connection>,
    ) -> Self {
        let mut composer = TextArea::default();
        composer.set_wrap_mode(WrapMode::WordOrGlyph);
        composer.set_max_rows(6);
        composer.set_placeholder_text("Write a message...");
        composer.set_tab_length(0);
        Self {
            user_id,
            composer,
            target_user: None,
            running: true,
            authenticated: false,
            crypto,
            last_typing_sent: None,
            status_bar: StatusBar::new(),
            pending_msg_ids: Vec::new(),
            unread_messages: HashMap::new(),
            identity_warnings: HashMap::new(),
            chat_history: Vec::new(),
            db,
            focus: Focus::Composer,
            modal: None,
            selected_conversation: None,
            message_scroll: 0,
            last_rendered_max_scroll: None,
            notice: None,
        }
    }

    pub(crate) fn status(&mut self, text: &str) {
        self.notice = Some(Notice {
            text: text.to_owned(),
            created_at: Instant::now(),
        });
    }

    pub(crate) fn notice_text(&self) -> Option<&str> {
        self.notice.as_ref().map(|notice| notice.text.as_str())
    }

    fn tick_notice(&mut self) {
        if self
            .notice
            .as_ref()
            .is_some_and(|notice| notice.created_at.elapsed() > Duration::from_secs(5))
        {
            self.notice = None;
        }
    }

    pub(crate) fn clear_input(&mut self) {
        self.composer.clear();
    }

    fn load_chat_history(&mut self, peer_id: &str) {
        self.chat_history.clear();
        self.message_scroll = 0;
        self.last_rendered_max_scroll = None;
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

    pub(crate) fn composer_text(&self) -> String {
        self.composer.lines().join("\n")
    }

    pub(crate) fn conversations(&self) -> Vec<String> {
        let mut peers = self
            .db
            .as_ref()
            .and_then(|conn| crate::db::list_conversation_peers(conn).ok())
            .unwrap_or_default();
        let mut seen: HashSet<String> = peers.iter().cloned().collect();
        for peer in self.crypto.session_peers() {
            if seen.insert(peer.to_owned()) {
                peers.push(peer.to_owned());
            }
        }
        for peer in self.crypto.pending_peers() {
            if seen.insert(peer.clone()) {
                peers.push(peer);
            }
        }
        for peer in self.unread_messages.keys() {
            if seen.insert(peer.clone()) {
                peers.push(peer.clone());
            }
        }
        let self_id = self.user_id.as_str().to_owned();
        if seen.insert(self_id.clone()) {
            peers.push(self_id);
        }
        peers
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

    let (mut terminal, _guard) = ui::init()?;
    let mut app = initialized_app(validated_uid, crypto, db);
    let mut event_stream = EventStream::new();
    let mut lifecycle_tick = tokio::time::interval(Duration::from_mins(1));
    lifecycle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    lifecycle_tick.tick().await;

    while app.running {
        ui::draw(&mut terminal, &mut app)?;

        let status_tick = async {
            if app.status_bar.needs_tick() || app.notice.is_some() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            Some(Ok(event)) = event_stream.next() => {
                crate::input::handle_key_event(&mut app, &outgoing_tx, event)?;
            }
            Some(event) = event_rx.recv() => {
                handle_app_event(&mut app, &outgoing_tx, event)?;
            }
            () = status_tick => {
                app.status_bar.tick();
                app.tick_notice();
            }
            _ = lifecycle_tick.tick() => {
                prekeys::handle_lifecycle_tick(&mut app, &outgoing_tx);
            }
        }
    }

    Ok(())
}

fn initialized_app(
    user_id: UserId,
    crypto: CryptoManager,
    db: Option<rusqlite::Connection>,
) -> App {
    let mut app = App::new(user_id, crypto, db);
    if app.db.is_none() {
        app.status("warning: message history unavailable");
    }
    app
}

fn dirs_data_dir(user_id: &str) -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    std::path::PathBuf::from(home).join(".cmp").join(user_id)
}

#[allow(clippy::cognitive_complexity)]
pub(crate) fn handle_enter(app: &mut App, outgoing_tx: &mpsc::UnboundedSender<ClientMessage>) {
    let text = app.composer_text().trim().to_owned();
    if text.is_empty() {
        return;
    }

    let Some(target) = app.target_user.clone() else {
        app.status("choose a conversation before sending");
        return;
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
            app.status("failed to save note");
            return;
        }
        app.chat_history.push(ChatEntry::Sent(text));
        app.clear_input();
        return;
    }

    if !app.crypto.has_session(target_str) {
        app.status("waiting for session establishment...");
        return;
    }
    if !app.authenticated {
        app.status("waiting for server connection...");
        return;
    }
    if prekeys::refresh_expired_session(app, outgoing_tx, &target) {
        return;
    }

    // Check plaintext size BEFORE encrypting to avoid ratchet desync
    let estimated_b64_len = (text.len() + 18) / 3 * 4;
    if estimated_b64_len > consts::MAX_CIPHERTEXT_BYTES {
        app.status("message too long");
        return;
    }

    let msg_id = MessageId::new();
    let outbound = match app
        .crypto
        .encrypt_message(target_str, &target, &msg_id, text.as_bytes())
    {
        Ok(message) => message,
        Err(e) => {
            app.status(&format!("encrypt error: {e}"));
            return;
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
}

pub(crate) fn open_conversation(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    target: &str,
) -> anyhow::Result<()> {
    let uid = UserId::new(target)?;
    app.load_chat_history(target);
    if let Some(warning) = app.identity_warnings.get(target) {
        app.chat_history.push(ChatEntry::Warning(warning.clone()));
    }
    app.target_user = Some(uid.clone());
    app.selected_conversation = Some(target.to_owned());
    app.focus = Focus::Composer;
    app.modal = None;
    app.status_bar.clear_typing();
    app.last_typing_sent = None;

    if target == app.user_id.as_str() {
        app.status("note to self");
        return Ok(());
    }
    if app.crypto.has_session(target) {
        app.status(&format!("E2EE active with {target}"));
        flush_read_receipts(app, outgoing_tx, &uid);
        return Ok(());
    }

    app.crypto.add_pending(target);
    if app.authenticated {
        let _ = outgoing_tx.send(ClientMessage::FetchPreKeyBundle {
            target_user_id: uid,
        });
        app.status(&format!("fetching keys for {target}..."));
    } else {
        app.status("waiting for server connection...");
    }
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
            prekeys::queue_signed_prekey_rotation(app);
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
                if app.target_user.is_none() {
                    open_conversation(app, outgoing_tx, &sender)?;
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
            if app
                .target_user
                .as_ref()
                .is_some_and(|target| target == &sender_id)
            {
                app.status_bar.set_typing(sender_id.as_str().to_owned());
            }
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
        ServerMessage::PreKeyLow { remaining } => {
            prekeys::handle_prekey_low(app, outgoing_tx, remaining);
        }
        ServerMessage::PreKeysUploaded {
            upload_id,
            accepted,
            remaining,
        } => prekeys::handle_prekeys_uploaded(app, outgoing_tx, &upload_id, accepted, remaining),
        ServerMessage::SignedPreKeyRotated {
            rotation_id,
            accepted,
            previously_accepted,
            current_key_id,
        } => prekeys::handle_signed_prekey_rotated(
            app,
            outgoing_tx,
            &rotation_id,
            accepted,
            previously_accepted,
            current_key_id,
        ),
        ServerMessage::Error { message, .. } => {
            app.status(&format!("server error: {message}"));
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn show_verification(app: &mut App, action: &str) {
    let Some(ref target) = app.target_user else {
        app.status("choose a conversation before verifying");
        return;
    };
    if target.as_str() == app.user_id.as_str() {
        app.status("note to self does not have a peer safety number");
        return;
    }
    let key = app.crypto.local_identity_key_b64();
    let uid = app.user_id.as_str();
    let entries =
        crate::verification::handle_action(uid, &key, target.as_str(), action, app.db.as_ref());
    let confirmed = app
        .db
        .as_ref()
        .and_then(|db| crate::db::get_verification(db, target.as_str()))
        .is_some();
    if action == "confirm" && confirmed {
        app.identity_warnings.remove(target.as_str());
    }
    app.modal = Some(Modal::Verification(entries));
}

/// Store a peer's identity key (from a `PreKey` header) and warn if it changed.
fn track_peer_identity(app: &mut App, peer_id: &str, identity_key_b64: &str) {
    if let Some(ref conn) = app.db
        && let Some(warning) =
            crate::verification::check_peer_identity(conn, peer_id, identity_key_b64)
    {
        app.identity_warnings
            .insert(peer_id.to_owned(), warning.clone());
        if app
            .target_user
            .as_ref()
            .is_some_and(|target| target.as_str() == peer_id)
        {
            app.chat_history.push(ChatEntry::Warning(warning));
        } else {
            app.status(&format!("security alert for {peer_id}"));
        }
    }
}

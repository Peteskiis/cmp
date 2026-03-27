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
}

impl App {
    const fn new(crypto: CryptoManager) -> Self {
        Self {
            input: String::new(),
            cursor_pos: 0,
            input_scroll: 0,
            target_user: None,
            running: true,
            crypto,
        }
    }

    fn clear_input(&mut self) {
        self.input.clear();
        self.cursor_pos = 0;
    }
}

pub async fn run(user_id: &str, server_url: &str) -> anyhow::Result<()> {
    let validated_uid = UserId::new(user_id)?;

    let data_dir = dirs_data_dir(user_id);
    let crypto = CryptoManager::load_or_generate(&data_dir)?;

    if let Err(e) = register_with_server(user_id, server_url, crypto.identity()).await {
        eprintln!("Registration: {e}");
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
    ui::insert_status(
        &mut terminal,
        "type /chat <username> to start a conversation",
    )?;

    let mut app = App::new(crypto);
    let mut event_stream = EventStream::new();

    while app.running {
        let term_width = terminal.size()?.width as usize;
        let max_visible = term_width.saturating_sub(4);
        update_scroll(&mut app, max_visible);
        let visible_input = visible_slice(&app.input, app.input_scroll, max_visible);
        let visible_cursor = app.cursor_pos.saturating_sub(app.input_scroll);

        ui::draw_input(&mut terminal, &visible_input, visible_cursor)?;

        tokio::select! {
            Some(Ok(event)) = event_stream.next() => {
                handle_key_event(&mut app, &mut terminal, &outgoing_tx, event)?;
            }
            Some(event) = event_rx.recv() => {
                handle_app_event(&mut app, &mut terminal, &outgoing_tx, event)?;
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
                app.target_user = Some(uid);
            }
            Err(e) => {
                ui::insert_status(terminal, &format!("invalid username: {e}"))?;
            }
        }
        app.clear_input();
        return Ok(());
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

    // Check plaintext size BEFORE encrypting to avoid ratchet desync.
    // Estimate: (plaintext + 16-byte AEAD tag + 2 padding) * 4/3 for base64
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

    let _ = outgoing_tx.send(ClientMessage::SendMessage {
        recipient_id: target.clone(),
        message_id: MessageId::new(),
        envelope,
    });
    ui::insert_user_message(terminal, &text)?;
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

#[allow(clippy::cognitive_complexity)]
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
            // Only ack if decryption succeeded — failed messages should be re-delivered
            if ok {
                let _ = outgoing_tx.send(ClientMessage::Ack {
                    message_ids: vec![inbound.message_id],
                });
            }
        }
        ServerMessage::QueuedMessages { messages } => {
            let mut ack_ids = Vec::with_capacity(messages.len());
            for inbound in messages {
                let sender = inbound.sender_id.as_str().to_owned();
                let (text, ok) = app.crypto.decrypt_to_text(&sender, &inbound.envelope);
                ui::insert_friend_message(terminal, &sender, &text)?;
                if ok {
                    ack_ids.push(inbound.message_id);
                }
            }
            if !ack_ids.is_empty() {
                let _ = outgoing_tx.send(ClientMessage::Ack {
                    message_ids: ack_ids,
                });
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

async fn register_with_server(
    user_id: &str,
    server_url: &str,
    identity: &crypto::keys::IdentityKeyPair,
) -> anyhow::Result<()> {
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
        return Ok(());
    }
    if let Ok(ServerMessage::AuthFailure { reason }) = serde_json::from_str(&text) {
        if reason.contains("already exists") {
            return Ok(());
        }
        anyhow::bail!("registration rejected: {reason}");
    }
    anyhow::bail!("unexpected server response during registration");
}

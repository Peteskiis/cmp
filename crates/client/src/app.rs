use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
use futures::StreamExt;
use protocol::{
    ClientMessage, EncryptedEnvelope, MessageId, ServerMessage, UserId, consts,
    types::{MessageHeader, RatchetHeader},
};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;

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

#[allow(dead_code)] // user_id needed for future features (message display, ack scoping)
struct App {
    user_id: String,
    input: String,
    cursor_pos: usize,
    /// Horizontal scroll offset for long input lines.
    input_scroll: usize,
    target_user: Option<String>,
    running: bool,
}

impl App {
    fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_owned(),
            input: String::new(),
            cursor_pos: 0,
            input_scroll: 0,
            target_user: None,
            running: true,
        }
    }
}

/// Main entry point.
pub async fn run(user_id: &str, server_url: &str) -> anyhow::Result<()> {
    // Validate user ID once at startup
    let validated_uid = UserId::new(user_id)?;

    // Generate ephemeral identity key (persistence deferred — see ROADMAP Phase 5 DB work)
    let identity = crypto::keys::IdentityKeyPair::generate();

    // Register with server first
    if let Err(e) = register_with_server(user_id, server_url, &identity).await {
        eprintln!("Registration failed: {e}");
        // Continue — might already be registered, auth will handle it
    }

    // Channels
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel::<ClientMessage>();

    // Spawn network task with pre-validated UserId
    let net_url = server_url.to_owned();
    let net_uid = validated_uid.clone();
    let net_identity = crypto::keys::IdentityKeyPair::from_bytes(&identity.to_bytes());
    tokio::spawn(async move {
        net::run(net_url, net_uid, &net_identity, event_tx, outgoing_rx).await;
    });

    // Set up inline TUI
    let (mut terminal, _guard) = ui::init()?;

    ui::insert_status(&mut terminal, &format!("logged in as {user_id}"))?;
    ui::insert_status(
        &mut terminal,
        "\u{26a0} messages are NOT encrypted (placeholder mode)",
    )?;
    ui::insert_status(
        &mut terminal,
        "type /chat <username> to start a conversation",
    )?;

    let mut app = App::new(user_id);
    let mut event_stream = EventStream::new();

    while app.running {
        // Compute visible input slice for horizontal scrolling
        let term_width = terminal.size()?.width as usize;
        let max_visible = term_width.saturating_sub(4); // 4 for " › " prefix
        update_scroll(&mut app, max_visible);
        let visible_input = visible_slice(&app.input, app.input_scroll, max_visible);
        let visible_cursor = app.cursor_pos.saturating_sub(app.input_scroll);

        ui::draw_input(&mut terminal, &visible_input, visible_cursor)?;

        tokio::select! {
            Some(Ok(event)) = event_stream.next() => {
                handle_key_event(&mut app, &mut terminal, &outgoing_tx, event)?;
            }
            Some(event) = event_rx.recv() => {
                handle_app_event(&app, &mut terminal, &outgoing_tx, event)?;
            }
        }
    }

    Ok(())
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
        // Only insert printable chars without control/alt modifiers
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

    // Handle /chat command — validate username immediately
    if let Some(target) = text.strip_prefix("/chat ") {
        let target = target.trim();
        match UserId::new(target) {
            Ok(_) => {
                app.target_user = Some(target.to_owned());
                ui::insert_status(terminal, &format!("chatting with {target}"))?;
            }
            Err(e) => {
                ui::insert_status(terminal, &format!("invalid username: {e}"))?;
            }
        }
        app.input.clear();
        app.cursor_pos = 0;
        return Ok(());
    }

    let Some(ref target) = app.target_user else {
        ui::insert_status(terminal, "use /chat <username> first")?;
        app.input.clear();
        app.cursor_pos = 0;
        return Ok(());
    };

    // Check message size limit before sending
    let ciphertext = B64.encode(text.as_bytes());
    if ciphertext.len() > consts::MAX_CIPHERTEXT_BYTES {
        ui::insert_status(terminal, "message too long")?;
        app.input.clear();
        app.cursor_pos = 0;
        return Ok(());
    }

    let envelope = EncryptedEnvelope {
        version: 1,
        header: MessageHeader::Ratchet(RatchetHeader {
            ratchet_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            previous_chain_length: 0,
            message_number: 0,
        }),
        ciphertext,
    };

    // Defensive re-validation — /chat validates at set time, but target could
    // theoretically be stale if validation rules change
    let Ok(recipient) = UserId::new(target.as_str()) else {
        ui::insert_status(terminal, "invalid recipient")?;
        app.input.clear();
        app.cursor_pos = 0;
        return Ok(());
    };

    let _ = outgoing_tx.send(ClientMessage::SendMessage {
        recipient_id: recipient,
        message_id: MessageId::new(),
        envelope,
    });
    ui::insert_user_message(terminal, &text)?;

    app.input.clear();
    app.cursor_pos = 0;
    Ok(())
}

fn handle_app_event(
    app: &App,
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

fn handle_server_message(
    _app: &App,
    terminal: &mut ui::Term,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    msg: ServerMessage,
) -> anyhow::Result<()> {
    match msg {
        ServerMessage::IncomingMessage(inbound) => {
            let sender = inbound.sender_id.as_str();
            let text = B64
                .decode(&inbound.envelope.ciphertext)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| "[encrypted message]".to_owned());
            ui::insert_friend_message(terminal, sender, &text)?;

            // Ack the message so the server removes it from the queue
            let _ = outgoing_tx.send(ClientMessage::Ack {
                message_ids: vec![inbound.message_id],
            });
        }
        ServerMessage::QueuedMessages { messages } => {
            let mut ack_ids = Vec::with_capacity(messages.len());
            for inbound in messages {
                let sender = inbound.sender_id.as_str();
                let text = B64
                    .decode(&inbound.envelope.ciphertext)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| "[encrypted message]".to_owned());
                ui::insert_friend_message(terminal, sender, &text)?;
                ack_ids.push(inbound.message_id);
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

/// Register with the server (first-time setup).
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

    // Read response — fail explicitly on unexpected/missing responses
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
            return Ok(()); // Already registered — will auth via challenge-response
        }
        anyhow::bail!("registration rejected: {reason}");
    }
    anyhow::bail!("unexpected server response during registration");
}

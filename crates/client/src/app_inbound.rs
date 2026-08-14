use protocol::{ClientMessage, MessageHeader, MessageId, UserId, consts};
use tokio::sync::mpsc;

use super::{App, ChatEntry, InboundDecrypt, track_peer_identity};

pub(super) fn queue_ack(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    message_ids: Vec<MessageId>,
) {
    if let Ok(ack) = app.crypto.queue_ack(message_ids) {
        let _ = outgoing_tx.send(ack);
    }
}

pub(super) fn queue_read_receipt_ack(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    receipt_ids: Vec<MessageId>,
) {
    if let Ok(ack) = app.crypto.queue_read_receipt_ack(receipt_ids) {
        let _ = outgoing_tx.send(ack);
    }
}

/// Decrypt an inbound message and push to chat history.
pub(super) fn process_inbound(
    app: &mut App,
    inbound: &protocol::InboundMessage,
) -> (String, MessageId, bool, bool) {
    let sender = inbound.sender_id.as_str().to_owned();
    match app
        .crypto
        .decrypt_message_to_text(&sender, &inbound.message_id, &inbound.envelope)
    {
        InboundDecrypt::Pending(text) => process_pending_inbound(app, inbound, sender, text),
        InboundDecrypt::Duplicate => (sender, inbound.message_id.clone(), true, false),
        InboundDecrypt::Failed => {
            if is_active_peer(app, &sender) {
                app.chat_history.push(ChatEntry::Received {
                    sender: sender.clone(),
                    text: "[undecryptable message]".to_owned(),
                });
            }
            (sender, inbound.message_id.clone(), false, false)
        }
    }
}

fn process_pending_inbound(
    app: &mut App,
    inbound: &protocol::InboundMessage,
    sender: String,
    text: String,
) -> (String, MessageId, bool, bool) {
    // Only store identity keys after AEAD authentication succeeds.
    if let MessageHeader::PreKey {
        sender_identity_key,
        ..
    } = &inbound.envelope.header
    {
        let identity_key = sender_identity_key;
        track_peer_identity(app, &sender, identity_key);
    }
    let Ok(inserted) = commit_pending_inbound(app, inbound, &sender, &text) else {
        tracing::warn!("failed to commit received message");
        return (sender, inbound.message_id.clone(), false, false);
    };
    if inserted && is_active_peer(app, &sender) {
        app.chat_history.push(ChatEntry::Received {
            sender: sender.clone(),
            text,
        });
    }
    (sender, inbound.message_id.clone(), true, inserted)
}

fn is_active_peer(app: &App, peer_id: &str) -> bool {
    app.target_user
        .as_ref()
        .is_some_and(|target| target.as_str() == peer_id)
}

fn commit_pending_inbound(
    app: &mut App,
    inbound: &protocol::InboundMessage,
    sender: &str,
    text: &str,
) -> anyhow::Result<bool> {
    let inserted = app.persist_message(
        sender,
        crate::db::MessageDirection::Received,
        &inbound.message_id.to_string(),
        text,
    )?;
    app.crypto
        .confirm_inbound_stored(sender, &inbound.message_id)?;
    Ok(inserted)
}

/// Encrypt and send pending read receipts for `target`.
pub(super) fn flush_read_receipts(
    app: &mut App,
    outgoing_tx: &mpsc::UnboundedSender<ClientMessage>,
    target: &UserId,
) {
    let target_str = target.as_str();
    if let Some(unread) = app.unread_messages.get(target_str)
        && !unread.is_empty()
        && app.crypto.has_session(target_str)
        && let Ok(receipt) = app.crypto.encrypt_read_receipt(target_str, target, unread)
    {
        let _ = outgoing_tx.send(receipt);
        app.unread_messages.remove(target_str);
    }
}

/// Push a message ID to the bounded unread list for a peer.
pub(super) fn accumulate_unread(app: &mut App, sender: String, message_id: MessageId) {
    let entry = app.unread_messages.entry(sender).or_default();
    if entry.len() < consts::MAX_RECEIPT_BATCH {
        entry.push(message_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_authenticated_message_stays_out_of_active_chat_until_selected() {
        let (mut alice_crypto, bob_crypto, _alice_dir, bob_dir) =
            crate::crypto_mgr::tests::setup_alice_and_bob();
        let db = crate::db::open(&bob_dir.path().join("client.db")).unwrap();
        let mut app = App::new(UserId::new("bob").unwrap(), bob_crypto, Some(db));
        app.target_user = Some(UserId::new("carol").unwrap());
        let message_id = MessageId::new();
        let inbound = protocol::InboundMessage {
            message_id: message_id.clone(),
            sender_id: UserId::new("alice").unwrap(),
            envelope: alice_crypto.encrypt("bob", b"private hello").unwrap(),
            timestamp: 0,
        };

        let (sender, received_id, should_ack, fresh) = process_inbound(&mut app, &inbound);
        if fresh {
            accumulate_unread(&mut app, sender, received_id);
        }

        assert!(should_ack);
        assert!(fresh);
        assert!(app.chat_history.is_empty());
        assert_eq!(app.unread_messages.get("alice"), Some(&vec![message_id]));

        let (tx, _rx) = mpsc::unbounded_channel();
        crate::app::open_conversation(&mut app, &tx, "alice").unwrap();

        assert!(app.chat_history.iter().any(|entry| matches!(
            entry,
            ChatEntry::Received { sender, text }
                if sender == "alice" && text == "private hello"
        )));
    }
}

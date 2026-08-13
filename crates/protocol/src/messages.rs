use serde::{Deserialize, Serialize};

use crate::types::{EncryptedEnvelope, MessageId, OneTimePreKey, PreKeyBundle, UserId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ClientMessage {
    /// Bundle must have `one_time_prekey: None` — the batch is sent separately
    /// in `one_time_prekeys`. Max `consts::MAX_PREKEYS_PER_UPLOAD` items.
    Register {
        user_id: UserId,
        bundle: PreKeyBundle,
        one_time_prekeys: Vec<OneTimePreKey>,
    },

    AuthChallenge {
        user_id: UserId,
    },

    /// Base64-encoded Ed25519 signature over `nonce || timestamp || server_id`.
    AuthResponse {
        signature: String,
    },

    /// Max `consts::MAX_PREKEYS_PER_UPLOAD` items.
    UploadPreKeys {
        upload_id: MessageId,
        prekeys: Vec<OneTimePreKey>,
    },

    RotateSignedPreKey {
        rotation_id: MessageId,
        key_id: u32,
        public_key: String,
        signature: String,
    },

    FetchPreKeyBundle {
        target_user_id: UserId,
    },

    SendMessage {
        recipient_id: UserId,
        message_id: MessageId,
        envelope: EncryptedEnvelope,
    },

    /// Acknowledge receipt of messages (allows server to delete from queue).
    /// Max `consts::MAX_ACK_BATCH` items.
    Ack {
        ack_id: MessageId,
        message_ids: Vec<MessageId>,
    },

    AckMessageSent {
        message_ids: Vec<MessageId>,
    },

    /// Ephemeral typing indicator — relayed to online recipient only, never queued.
    Typing {
        recipient_id: UserId,
    },

    /// E2EE encrypted read receipt — relayed to online recipient only, never queued.
    SendReadReceipt {
        recipient_id: UserId,
        receipt_id: MessageId,
        envelope: EncryptedEnvelope,
    },

    AckReadReceipt {
        ack_id: MessageId,
        receipt_ids: Vec<MessageId>,
    },
    AckReadReceiptSent {
        receipt_ids: Vec<MessageId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ServerMessage {
    /// Login challenge — client must sign `nonce || timestamp || server_id`.
    Challenge {
        /// Base64-encoded 32-byte random nonce.
        nonce: String,
        /// Seconds since Unix epoch. Client must respond within 60s.
        timestamp: u64,
        server_id: String,
    },

    AuthSuccess,

    AuthFailure {
        reason: String,
    },

    PreKeyBundleResponse {
        user_id: UserId,
        bundle: PreKeyBundle,
    },

    IncomingMessage(InboundMessage),

    /// Max `consts::MAX_QUEUED_MESSAGES_PER_PAGE` items and
    /// `consts::MAX_QUEUED_PAGE_BYTES` encoded bytes per response.
    QueuedMessages {
        messages: Vec<InboundMessage>,
    },

    MessageSent {
        message_id: MessageId,
    },

    MessageRejected {
        message_id: MessageId,
        reason: String,
    },

    AckSuccess {
        ack_id: MessageId,
        message_ids: Vec<MessageId>,
    },

    ReadReceiptSent {
        receipt_id: MessageId,
    },

    /// Generic success acknowledgment (e.g., prekey upload).
    Success,

    /// Server alerts that one-time pre-keys are running low.
    PreKeyLow {
        remaining: u32,
    },

    PreKeysUploaded {
        upload_id: MessageId,
        accepted: bool,
        remaining: u32,
    },

    SignedPreKeyRotated {
        rotation_id: MessageId,
        accepted: bool,
    },

    Error {
        code: u32,
        message: String,
    },

    /// A peer is currently typing. Ephemeral — never queued.
    PeerTyping {
        sender_id: UserId,
    },

    /// Server-generated: message was pushed to recipient's device.
    MessageDelivered {
        message_ids: Vec<MessageId>,
    },

    /// E2EE encrypted read receipt from a peer.
    IncomingReadReceipt {
        sender_id: UserId,
        receipt_id: MessageId,
        envelope: EncryptedEnvelope,
    },
}

/// A message from another user, used for both live delivery and queued messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundMessage {
    pub message_id: MessageId,
    pub sender_id: UserId,
    pub envelope: EncryptedEnvelope,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MessageHeader, RatchetHeader};

    fn sample_ratchet_header() -> RatchetHeader {
        RatchetHeader {
            ratchet_key: "cmF0Y2hldA==".to_owned(),
            previous_chain_length: 0,
            message_number: 0,
        }
    }

    fn sample_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: 1,
            header: MessageHeader::Ratchet(sample_ratchet_header()),
            ciphertext: "Y2lwaGVydGV4dA==".to_owned(),
        }
    }

    fn sample_prekey_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: 1,
            header: MessageHeader::PreKey {
                sender_identity_key: "c2VuZGVyX2lk".to_owned(),
                sender_ephemeral_key: "ZXBoZW1lcmFs".to_owned(),
                recipient_signed_prekey_id: 1,
                recipient_one_time_prekey_id: Some(42),
                ratchet: sample_ratchet_header(),
            },
            ciphertext: "Y2lwaGVydGV4dA==".to_owned(),
        }
    }

    fn sample_bundle() -> PreKeyBundle {
        PreKeyBundle {
            identity_key: "aWRlbnRpdHk=".to_owned(),
            signed_prekey: "c2lnbmVk".to_owned(),
            signed_prekey_id: 1,
            signed_prekey_signature: "c2ln".to_owned(),
            one_time_prekey: Some(OneTimePreKey {
                key_id: 42,
                public_key: "b3Br".to_owned(),
            }),
        }
    }

    fn user(name: &str) -> UserId {
        UserId::new(name).expect("valid test user id")
    }

    fn roundtrip_client(msg: &ClientMessage) {
        let json = serde_json::to_string(msg).expect("serialize");
        let back: ClientMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back, msg);
    }

    fn roundtrip_server(msg: &ServerMessage) {
        let json = serde_json::to_string(msg).expect("serialize");
        let back: ServerMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back, msg);
    }

    // ── ClientMessage round-trips ──

    #[test]
    fn client_register() {
        roundtrip_client(&ClientMessage::Register {
            user_id: user("alice"),
            bundle: PreKeyBundle {
                identity_key: "aWQ=".to_owned(),
                signed_prekey: "c3Br".to_owned(),
                signed_prekey_id: 0,
                signed_prekey_signature: "c2ln".to_owned(),
                one_time_prekey: None,
            },
            one_time_prekeys: vec![
                OneTimePreKey {
                    key_id: 0,
                    public_key: "a2V5MA==".to_owned(),
                },
                OneTimePreKey {
                    key_id: 1,
                    public_key: "a2V5MQ==".to_owned(),
                },
            ],
        });
    }

    #[test]
    fn client_auth_challenge() {
        roundtrip_client(&ClientMessage::AuthChallenge {
            user_id: user("bob"),
        });
    }

    #[test]
    fn client_auth_response() {
        roundtrip_client(&ClientMessage::AuthResponse {
            signature: "c2ln".to_owned(),
        });
    }

    #[test]
    fn client_upload_prekeys() {
        roundtrip_client(&ClientMessage::UploadPreKeys {
            upload_id: MessageId::new(),
            prekeys: vec![OneTimePreKey {
                key_id: 5,
                public_key: "cGs=".to_owned(),
            }],
        });
    }

    #[test]
    fn client_rotate_signed_prekey() {
        roundtrip_client(&ClientMessage::RotateSignedPreKey {
            rotation_id: MessageId::new(),
            key_id: 2,
            public_key: "cGs=".to_owned(),
            signature: "c2ln".to_owned(),
        });
    }

    #[test]
    fn client_fetch_prekey_bundle() {
        roundtrip_client(&ClientMessage::FetchPreKeyBundle {
            target_user_id: user("carol"),
        });
    }

    #[test]
    fn client_send_message() {
        roundtrip_client(&ClientMessage::SendMessage {
            recipient_id: user("bob"),
            message_id: MessageId::new(),
            envelope: sample_envelope(),
        });
    }

    #[test]
    fn client_send_prekey_message() {
        roundtrip_client(&ClientMessage::SendMessage {
            recipient_id: user("bob"),
            message_id: MessageId::new(),
            envelope: sample_prekey_envelope(),
        });
    }

    #[test]
    fn client_ack() {
        roundtrip_client(&ClientMessage::Ack {
            ack_id: MessageId::new(),
            message_ids: vec![MessageId::new(), MessageId::new()],
        });
    }

    #[test]
    fn client_ack_read_receipt_sent() {
        roundtrip_client(&ClientMessage::AckReadReceiptSent {
            receipt_ids: vec![MessageId::new()],
        });
    }

    // ── ServerMessage round-trips ──

    #[test]
    fn server_challenge() {
        roundtrip_server(&ServerMessage::Challenge {
            nonce: "bm9uY2U=".to_owned(),
            timestamp: 1_700_000_000,
            server_id: "srv-1".to_owned(),
        });
    }

    #[test]
    fn server_auth_success() {
        roundtrip_server(&ServerMessage::AuthSuccess);
    }

    #[test]
    fn server_auth_failure() {
        roundtrip_server(&ServerMessage::AuthFailure {
            reason: "bad sig".to_owned(),
        });
    }

    #[test]
    fn server_prekey_bundle_response() {
        roundtrip_server(&ServerMessage::PreKeyBundleResponse {
            user_id: user("bob"),
            bundle: sample_bundle(),
        });
    }

    #[test]
    fn server_incoming_message() {
        roundtrip_server(&ServerMessage::IncomingMessage(InboundMessage {
            message_id: MessageId::new(),
            sender_id: user("alice"),
            envelope: sample_envelope(),
            timestamp: 1_700_000_001,
        }));
    }

    #[test]
    fn server_queued_messages() {
        roundtrip_server(&ServerMessage::QueuedMessages {
            messages: vec![InboundMessage {
                message_id: MessageId::new(),
                sender_id: user("alice"),
                envelope: sample_envelope(),
                timestamp: 1_700_000_002,
            }],
        });
    }

    #[test]
    fn server_message_sent() {
        roundtrip_server(&ServerMessage::MessageSent {
            message_id: MessageId::new(),
        });
    }

    #[test]
    fn server_success() {
        roundtrip_server(&ServerMessage::Success);
    }

    #[test]
    fn server_prekey_low() {
        roundtrip_server(&ServerMessage::PreKeyLow { remaining: 3 });
    }

    #[test]
    fn server_prekeys_uploaded() {
        roundtrip_server(&ServerMessage::PreKeysUploaded {
            upload_id: MessageId::new(),
            accepted: true,
            remaining: 100,
        });
    }

    #[test]
    fn server_signed_prekey_rotated() {
        roundtrip_server(&ServerMessage::SignedPreKeyRotated {
            rotation_id: MessageId::new(),
            accepted: true,
        });
    }

    #[test]
    fn server_error() {
        roundtrip_server(&ServerMessage::Error {
            code: 429,
            message: "rate limited".to_owned(),
        });
    }

    // ── Envelope variants ──

    #[test]
    fn envelope_ratchet_roundtrip() {
        let envelope = sample_envelope();
        let json = serde_json::to_string(&envelope).expect("serialize");
        let back: EncryptedEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, envelope);
    }

    #[test]
    fn envelope_prekey_roundtrip() {
        let envelope = sample_prekey_envelope();
        let json = serde_json::to_string(&envelope).expect("serialize");
        let back: EncryptedEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, envelope);
    }

    // ── Forward compatibility ──

    #[test]
    fn unknown_fields_ignored() {
        let json = r#"{"type":"AuthSuccess","extra_field":"ignored"}"#;
        let msg: ServerMessage = serde_json::from_str(json).expect("deserialize");
        assert_eq!(msg, ServerMessage::AuthSuccess);
    }

    // ── UserId validation ──

    #[test]
    fn user_id_rejects_empty() {
        assert!(UserId::new("").is_err());
    }

    #[test]
    fn user_id_rejects_control_chars() {
        assert!(UserId::new("alice\0").is_err());
        assert!(UserId::new("bob\n").is_err());
    }

    #[test]
    fn user_id_rejects_oversized() {
        let long = "a".repeat(129);
        assert!(UserId::new(long).is_err());
    }

    #[test]
    fn user_id_deserialization_validates() {
        let json = r#"{"type":"AuthChallenge","user_id":""}"#;
        assert!(serde_json::from_str::<ClientMessage>(json).is_err());

        let json = r#"{"type":"AuthChallenge","user_id":"alice\u0000"}"#;
        assert!(serde_json::from_str::<ClientMessage>(json).is_err());
    }

    #[test]
    fn user_id_rejects_whitespace_only() {
        assert!(UserId::new("   ").is_err());
        assert!(UserId::new(" \t ").is_err());
    }

    #[test]
    fn user_id_rejects_path_traversal() {
        assert!(UserId::new("../etc").is_err());
        assert!(UserId::new("foo/bar").is_err());
        assert!(UserId::new("foo\\bar").is_err());
        assert!(UserId::new("a..b").is_err());
    }

    #[test]
    fn user_id_rejects_non_ascii() {
        assert!(UserId::new("café").is_err());
        assert!(UserId::new("用户").is_err());
    }

    #[test]
    fn user_id_accepts_valid() {
        assert!(UserId::new("alice").is_ok());
        assert!(UserId::new("user-123_test").is_ok());
        assert!(UserId::new("a".repeat(128)).is_ok());
    }

    #[test]
    fn unknown_variant_rejected() {
        let json = r#"{"type":"FooBar"}"#;
        assert!(serde_json::from_str::<ServerMessage>(json).is_err());
        assert!(serde_json::from_str::<ClientMessage>(json).is_err());
    }

    // ── Typing + receipt round-trips ──

    #[test]
    fn client_typing() {
        roundtrip_client(&ClientMessage::Typing {
            recipient_id: user("bob"),
        });
    }

    #[test]
    fn client_ack_message_sent() {
        roundtrip_client(&ClientMessage::AckMessageSent {
            message_ids: vec![MessageId::new()],
        });
    }

    #[test]
    fn client_send_read_receipt() {
        roundtrip_client(&ClientMessage::SendReadReceipt {
            recipient_id: user("bob"),
            receipt_id: MessageId::new(),
            envelope: sample_envelope(),
        });
    }

    #[test]
    fn server_peer_typing() {
        roundtrip_server(&ServerMessage::PeerTyping {
            sender_id: user("alice"),
        });
    }

    #[test]
    fn server_message_delivered() {
        roundtrip_server(&ServerMessage::MessageDelivered {
            message_ids: vec![MessageId::new(), MessageId::new()],
        });
    }

    #[test]
    fn server_message_rejected() {
        roundtrip_server(&ServerMessage::MessageRejected {
            message_id: MessageId::new(),
            reason: "expired reservation".to_owned(),
        });
    }

    #[test]
    fn server_incoming_read_receipt() {
        roundtrip_server(&ServerMessage::IncomingReadReceipt {
            sender_id: user("alice"),
            receipt_id: MessageId::new(),
            envelope: sample_envelope(),
        });
    }
}

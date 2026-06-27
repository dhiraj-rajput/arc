//! Session state machine
//! Every arc session MUST follow the formal state machine defined here.
//! Messages received in unexpected states are rejected with a protocol error.
//! This enforces the security invariants at the protocol layer.

use crate::protocol::messages::ArcMessage;
use thiserror::Error;

/// All possible states of an arc session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// No connection established.
    Idle,
    /// Transport connected; awaiting Hello/HelloAck exchange.
    Connected,
    /// Hello exchanged; awaiting AuthChallenge/AuthResponse.
    Authenticating,
    /// Authenticated; awaiting TransferOffer or ClipboardSync.
    Negotiating,
    /// Transfer in progress (chunks flowing).
    Transferring,
    /// All chunks received; verifying BLAKE3 root.
    Completing,
    /// Transfer done; session is reusable for another transfer.
    IdleReady,
    /// Session terminated (gracefully or due to error).
    Closed,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionState::Idle => write!(f, "Idle"),
            SessionState::Connected => write!(f, "Connected"),
            SessionState::Authenticating => write!(f, "Authenticating"),
            SessionState::Negotiating => write!(f, "Negotiating"),
            SessionState::Transferring => write!(f, "Transferring"),
            SessionState::Completing => write!(f, "Completing"),
            SessionState::IdleReady => write!(f, "IdleReady"),
            SessionState::Closed => write!(f, "Closed"),
        }
    }
}

/// Protocol error for illegal state transitions.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("illegal message '{message_type}' in state '{state}'")]
    IllegalMessageForState {
        state: String,
        message_type: &'static str,
    },
    #[error("session is already closed")]
    SessionClosed,
    #[error("relay compromise detected: {0} members in 2-party room")]
    RelayCompromised(u8),
}

/// Validate that a message is legal to receive in the given state.
///
/// Returns `Ok(())` if the message is legal, or a `ProtocolError` otherwise.
///
/// INV-9 is checked here: `RoomMemberCount > 2` triggers `RelayCompromised`.
pub fn validate_message_for_state(
    msg: &ArcMessage,
    state: &SessionState,
) -> Result<(), ProtocolError> {
    if matches!(state, SessionState::Closed) {
        return Err(ProtocolError::SessionClosed);
    }

    // INV-9: Relay room integrity check — triggers from any state
    if let ArcMessage::RoomMemberCount { count } = msg {
        if *count > 2 {
            return Err(ProtocolError::RelayCompromised(*count));
        }
        return Ok(()); // count ≤ 2: legal from any state
    }

    // Ping/Pong: legal from any non-Closed state
    if matches!(msg, ArcMessage::Ping { .. } | ArcMessage::Pong { .. }) {
        return Ok(());
    }

    match (state, msg) {
        // IDLE: hello only
        (SessionState::Idle, ArcMessage::Hello { .. }) => Ok(()),

        // CONNECTED: Hello/HelloAck only
        (SessionState::Connected, ArcMessage::Hello { .. }) => Ok(()),
        (SessionState::Connected, ArcMessage::HelloAck { .. }) => Ok(()),

        // AUTHENTICATING: auth messages only
        (SessionState::Authenticating, ArcMessage::AuthChallenge { .. }) => Ok(()),
        (SessionState::Authenticating, ArcMessage::AuthResponse { .. }) => Ok(()),
        (SessionState::Authenticating, ArcMessage::AuthOk) => Ok(()),
        (SessionState::Authenticating, ArcMessage::AuthFail { .. }) => Ok(()),

        // NEGOTIATING: transfer offer/accept/reject, goodbye
        (SessionState::Negotiating, ArcMessage::TransferOffer { .. }) => Ok(()),
        (SessionState::Negotiating, ArcMessage::TransferAccept { .. }) => Ok(()),
        (SessionState::Negotiating, ArcMessage::TransferReject { .. }) => Ok(()),
        (SessionState::Negotiating, ArcMessage::Goodbye { .. }) => Ok(()),

        // TRANSFERRING: chunk messages, file metadata, abort
        (SessionState::Transferring, ArcMessage::Chunk { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::ChunkAck { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::ChunkNak { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::FileMetadata { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::TransferComplete { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::TransferAbort { .. }) => Ok(()),

        // COMPLETING: only TransferComplete and TransferAbort
        (SessionState::Completing, ArcMessage::TransferComplete { .. }) => Ok(()),
        (SessionState::Completing, ArcMessage::TransferAbort { .. }) => Ok(()),

        // IDLE_READY: new offer or goodbye
        (SessionState::IdleReady, ArcMessage::TransferOffer { .. }) => Ok(()),
        (SessionState::IdleReady, ArcMessage::Goodbye { .. }) => Ok(()),

        // Everything else: illegal transition
        (state, msg) => Err(ProtocolError::IllegalMessageForState {
            state: state.to_string(),
            message_type: msg.type_name(),
        }),
    }
}

/// The state machine transition logic.
///
/// Returns the next state for a given (current_state, received_message) pair.
/// Returns None if no transition is defined (caller should use validate_message_for_state first).
pub fn next_state(state: &SessionState, msg: &ArcMessage) -> Option<SessionState> {
    match (state, msg) {
        (SessionState::Idle, ArcMessage::Hello { .. }) => Some(SessionState::Connected),

        (SessionState::Connected, ArcMessage::HelloAck { .. }) => Some(SessionState::Authenticating),
        (SessionState::Connected, ArcMessage::Hello { .. }) => Some(SessionState::Authenticating),

        (SessionState::Authenticating, ArcMessage::AuthOk) => Some(SessionState::Negotiating),
        (SessionState::Authenticating, ArcMessage::AuthFail { .. }) => Some(SessionState::Closed),

        (SessionState::Negotiating, ArcMessage::TransferAccept { .. }) => Some(SessionState::Transferring),
        (SessionState::Negotiating, ArcMessage::TransferReject { .. }) => Some(SessionState::Negotiating),
        (SessionState::Negotiating, ArcMessage::Goodbye { .. }) => Some(SessionState::Closed),

        (SessionState::Transferring, ArcMessage::TransferComplete { .. }) => Some(SessionState::Completing),
        (SessionState::Transferring, ArcMessage::TransferAbort { .. }) => Some(SessionState::Closed),

        (SessionState::Completing, ArcMessage::TransferComplete { .. }) => Some(SessionState::IdleReady),
        (SessionState::Completing, ArcMessage::TransferAbort { .. }) => Some(SessionState::Closed),

        (SessionState::IdleReady, ArcMessage::TransferOffer { .. }) => Some(SessionState::Negotiating),
        (SessionState::IdleReady, ArcMessage::Goodbye { .. }) => Some(SessionState::Closed),

        // Any state: relay compromise → Closed
        (_, ArcMessage::RoomMemberCount { count }) if *count > 2 => Some(SessionState::Closed),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::messages::{ArcMessage, AuthFailReason};

    fn hello_msg() -> ArcMessage {
        ArcMessage::Hello {
            protocol_version: 1,
            device_id: [0; 32],
            nonce: [0; 32],
            capabilities: vec![],
        }
    }

    #[test]
    fn test_hello_legal_in_connected() {
        assert!(validate_message_for_state(&hello_msg(), &SessionState::Connected).is_ok());
    }

    #[test]
    fn test_hello_illegal_in_transferring() {
        assert!(validate_message_for_state(&hello_msg(), &SessionState::Transferring).is_err());
    }

    #[test]
    fn test_ping_legal_in_any_state() {
        let ping = ArcMessage::Ping { timestamp_ms: 0 };
        for state in [
            SessionState::Connected,
            SessionState::Authenticating,
            SessionState::Negotiating,
            SessionState::Transferring,
            SessionState::Completing,
            SessionState::IdleReady,
        ] {
            assert!(
                validate_message_for_state(&ping, &state).is_ok(),
                "Ping must be legal in state {state}"
            );
        }
    }

    #[test]
    fn test_room_member_3_triggers_compromise() {
        let msg = ArcMessage::RoomMemberCount { count: 3 };
        let result = validate_message_for_state(&msg, &SessionState::Transferring);
        assert!(
            matches!(result, Err(ProtocolError::RelayCompromised(3))),
            "3 members must trigger RelayCompromised"
        );
    }

    #[test]
    fn test_room_member_2_is_ok() {
        let msg = ArcMessage::RoomMemberCount { count: 2 };
        assert!(validate_message_for_state(&msg, &SessionState::Transferring).is_ok());
    }

    #[test]
    fn test_closed_session_rejects_all() {
        let msg = ArcMessage::Ping { timestamp_ms: 0 };
        assert!(
            matches!(
                validate_message_for_state(&msg, &SessionState::Closed),
                Err(ProtocolError::SessionClosed)
            ),
            "closed session must reject all messages"
        );
    }

    #[test]
    fn test_auth_fail_transitions_to_closed() {
        let msg = ArcMessage::AuthFail { reason: AuthFailReason::BadSignature };
        let next = next_state(&SessionState::Authenticating, &msg);
        assert_eq!(next, Some(SessionState::Closed));
    }

    #[test]
    fn test_state_machine_happy_path() {
        // Simulate a complete session state progression
        let states = [
            (SessionState::Connected, hello_msg(), SessionState::Authenticating),
            (
                SessionState::Authenticating,
                ArcMessage::AuthOk,
                SessionState::Negotiating,
            ),
        ];

        for (current, msg, expected_next) in &states {
            let next = next_state(current, msg)
                .unwrap_or_else(|| panic!("no transition for {current} + {}", msg.type_name()));
            assert_eq!(&next, expected_next, "wrong transition from {current}");
        }
    }
}

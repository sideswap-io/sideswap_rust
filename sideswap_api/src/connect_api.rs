use elements::{schnorr::XOnlyPublicKey, secp256k1_zkp::schnorr::Signature};
use serde::{Deserialize, Serialize};
use sideswap_types::duration_ms::DurationMs;

// Common

pub type ReqId = i32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub request_id: String,
    pub domain: String,
    pub ttl: DurationMs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub request_id: String,
    pub domain: String,
    pub pset: String,
    pub ttl: DurationMs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserAction {
    LinkLoginRequest {
        request_id: String,
    },

    AcceptLoginRequest {
        request_id: String,
        descriptor: String,
    },

    CancelLoginRequest {
        request_id: String,
    },

    AcceptSignRequest {
        request_id: String,
        pset: String,
    },

    CancelSignRequest {
        request_id: String,
    },

    StopSession {
        session_id: String,
    },
}

// Requests

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeReq {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResp {
    pub challenge: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginReq {
    pub public_key: XOnlyPublicKey,
    pub signature: Signature,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResp {
    pub sessions: Vec<Session>,
    pub sign_requests: Vec<SignRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserActionReq {
    pub action: UserAction,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserActionResp {}

// Notifications

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionCreatedNotif {
    pub session: Session,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRemovedNotif {
    pub session_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequestCreatedNotif {
    pub request: LoginRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequestRemovedNotif {
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequestCreatedNotif {
    pub request: SignRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequestRemovedNotif {
    pub request_id: String,
}

// Top level messages

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Something wrong with the request arguments.
    InvalidRequest,
    /// Server error.
    Server,
    /// Unknown error
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub enum Req {
    Challenge(ChallengeReq),
    Login(LoginReq),
    UserAction(UserActionReq),
}

#[derive(Serialize, Deserialize)]
pub enum Resp {
    Challenge(ChallengeResp),
    Login(LoginResp),
    UserAction(UserActionResp),
}

#[derive(Serialize, Deserialize)]
pub enum Notif {
    SessionCreated(SessionCreatedNotif),
    SessionRemoved(SessionRemovedNotif),
    LoginRequestCreated(LoginRequestCreatedNotif),
    LoginRequestRemoved(LoginRequestRemovedNotif),
    SignRequestCreated(SignRequestCreatedNotif),
    SignRequestRemoved(SignRequestRemovedNotif),
}

#[derive(Serialize, Deserialize)]
pub enum To {
    Req { id: ReqId, req: Req },
}

#[derive(Serialize, Deserialize)]
pub enum From {
    Resp { id: ReqId, resp: Resp },
    Error { id: ReqId, err: Error },
    Notif { notif: Notif },
}

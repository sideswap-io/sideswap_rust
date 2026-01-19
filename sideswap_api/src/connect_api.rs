use serde::{Deserialize, Serialize};

// Common

pub type ReqId = i32;

// Requests

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeReq {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResp {
    pub challenge: String,
}

// Notifications

#[derive(Debug, Serialize, Deserialize)]
pub struct SignOrderNotif {}

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
}

#[derive(Serialize, Deserialize)]
pub enum Resp {
    Challenge(ChallengeResp),
}

#[derive(Serialize, Deserialize)]
pub enum Notif {
    SignOrder(SignOrderNotif),
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

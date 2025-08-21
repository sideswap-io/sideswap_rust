use serde::{Deserialize, Serialize};

// Common

pub type ReqId = i32;

// Requests

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterReq {}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterResp {}

// Notifications

#[derive(Debug, Serialize, Deserialize)]
pub struct UnregisteredNotif {}

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
    Register(RegisterReq),
}

#[derive(Serialize, Deserialize)]
pub enum Resp {
    Register(RegisterResp),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Notif {
    Unregistered(UnregisteredNotif),
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

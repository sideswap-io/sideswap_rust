use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct StartedReq {
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartedResp {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectedReq {
    pub code: String,
    pub descriptor: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectedResp {}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectedReq {
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectedResp {}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedReq {
    pub code: String,
    pub pset: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedResp {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Req {
    Started(StartedReq),
    Connected(ConnectedReq),
    Rejected(RejectedReq),
    Signed(SignedReq),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resp {
    Started(StartedResp),
    Connected(ConnectedResp),
    Rejected(RejectedResp),
    Signed(SignedResp),
}

#[derive(Serialize, Deserialize)]
pub struct Error {
    pub error: String,
}

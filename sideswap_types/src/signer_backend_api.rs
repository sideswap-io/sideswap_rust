use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct StartLoginReq {
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartLoginResp {}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptLoginReq {
    pub code: String,
    pub descriptor: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptLoginResp {}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectLoginReq {
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectLoginResp {}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartSignReq {
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartSignResp {
    pub pset: String,
    pub ttl_milliseconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptSignReq {
    pub code: String,
    pub pset: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptSignResp {}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectSignReq {
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RejectSignResp {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Req {
    StartLogin(StartLoginReq),
    AcceptLogin(AcceptLoginReq),
    RejectLogin(RejectLoginReq),
    StartSign(StartSignReq),
    AcceptSign(AcceptSignReq),
    RejectSign(RejectSignReq),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resp {
    StartLogin(StartLoginResp),
    AcceptLogin(AcceptLoginResp),
    RejectLogin(RejectLoginResp),
    StartSign(StartSignResp),
    AcceptSign(AcceptSignResp),
    RejectSign(RejectSignResp),
}

#[derive(Serialize, Deserialize)]
pub struct Error {
    pub error: String,
}

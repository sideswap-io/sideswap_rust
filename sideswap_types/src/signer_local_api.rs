use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginReq {}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResp {
    pub descriptor: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignReq {
    pub pset: String,
    pub blinding_nonces: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResp {
    pub pset: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Req {
    Login(LoginReq),
    Sign(SignReq),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resp {
    Login(LoginResp),
    Sign(SignResp),
}

#[derive(Serialize, Deserialize)]
pub struct Error {
    pub error: String,
}

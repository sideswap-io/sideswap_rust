use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DescriptorReq {}

#[derive(Debug, Serialize, Deserialize)]
pub struct DescriptorResp {
    pub descriptor: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignReq {
    pub pset: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResp {
    pub pset: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Req {
    Descriptor(DescriptorReq),
    Sign(SignReq),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resp {
    Descriptor(DescriptorResp),
    Sign(SignResp),
}

#[derive(Serialize, Deserialize)]
pub struct Error {
    pub error: String,
}

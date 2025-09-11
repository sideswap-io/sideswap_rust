use crate::network::Network;

#[derive(Debug, Eq, PartialEq, Copy, Clone, serde::Serialize, serde::Deserialize)]
pub enum Env {
    Prod,
    Testnet,
    LocalLiquid,
    LocalTestnet,
    LocalRegtest,
}

pub struct EnvData {
    pub host: &'static str,
    pub port: u16,
    pub use_tls: bool,
    pub name: &'static str,
    pub mainnet: bool,
    pub network: Network,
    pub wallet_port: u16,
}

const ENV_PROD: EnvData = EnvData {
    host: "api.sideswap.io",
    port: 443,
    use_tls: true,
    name: "prod",
    mainnet: true,
    network: Network::Liquid,
    wallet_port: 41687,
};

const ENV_TESTNET: EnvData = EnvData {
    host: "api-testnet.sideswap.io",
    port: 443,
    use_tls: true,
    name: "testnet",
    mainnet: false,
    network: Network::LiquidTestnet,
    wallet_port: 41688,
};

const ENV_LOCAL_LIQUID: EnvData = EnvData {
    host: "192.168.71.50",
    port: 5001,
    use_tls: false,
    name: "local_liquid",
    mainnet: true,
    network: Network::Liquid,
    wallet_port: 41689,
};

const ENV_LOCAL_TESTNET: EnvData = EnvData {
    host: "192.168.71.50",
    port: 6001,
    use_tls: false,
    name: "local_testnet",
    mainnet: false,
    network: Network::LiquidTestnet,
    wallet_port: 41690,
};

const ENV_LOCAL_REGTEST: EnvData = EnvData {
    host: "127.0.0.1",
    port: 22615,
    use_tls: false,
    name: "local_regtest",
    mainnet: false,
    network: Network::Regtest,
    wallet_port: 41691,
};

impl Env {
    pub fn d(&self) -> &'static EnvData {
        match *self {
            Env::Prod => &ENV_PROD,
            Env::Testnet => &ENV_TESTNET,
            Env::LocalLiquid => &ENV_LOCAL_LIQUID,
            Env::LocalTestnet => &ENV_LOCAL_TESTNET,
            Env::LocalRegtest => &ENV_LOCAL_REGTEST,
        }
    }

    pub fn nd(&self) -> &'static crate::network::NetworkData {
        self.d().network.d()
    }

    pub fn elements_params(&self) -> &'static elements::AddressParams {
        self.nd().elements_params
    }

    pub fn base_server_http_url(&self) -> String {
        let data = self.d();
        let protocol = if data.use_tls { "https" } else { "http" };
        format!("{}://{}:{}", protocol, data.host, data.port)
    }

    pub fn base_server_ws_url(&self) -> String {
        let data = self.d();
        let protocol = if data.use_tls { "wss" } else { "ws" };
        format!("{}://{}:{}", protocol, data.host, data.port)
    }
}

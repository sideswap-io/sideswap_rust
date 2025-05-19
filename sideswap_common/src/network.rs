use crate::const_asset_id::const_asset_id;

#[derive(Debug, Eq, PartialEq, Copy, Clone, serde::Serialize, serde::Deserialize)]
pub enum Network {
    Liquid,
    LiquidTestnet,
    Regtest,
}

impl Network {
    pub fn to_bitcoin_network(self) -> bitcoin::Network {
        match self {
            Network::Liquid => bitcoin::Network::Bitcoin,
            Network::LiquidTestnet => bitcoin::Network::Testnet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
pub struct KnownAssetIds {
    // Stablecoin
    pub USDt: elements::AssetId,
    pub EURx: elements::AssetId,
    pub MEX: elements::AssetId,
    pub DePix: elements::AssetId,

    // AMP
    pub SSWP: elements::AssetId,
}

impl KnownAssetIds {
    pub fn all_assets(&self) -> impl Iterator<Item = elements::AssetId> {
        [self.USDt, self.EURx, self.DePix, self.MEX, self.SSWP]
            .into_iter()
            .map(|asset| asset)
    }
}

pub struct NetworkData {
    pub name: &'static str,
    pub elements_params: &'static elements::address::AddressParams,
    pub bitcoin_network: bitcoin::Network,
    pub account_path_sh_wpkh: [u32; 3],
    pub account_path_wpkh: [u32; 3],
    pub electrum_url: &'static str,
    pub electrum_tls: bool,
    pub asset_registry_url: &'static str,
    pub tx_explorer_url: &'static str,
    pub address_explorer_url: &'static str,
    pub policy_asset: elements::AssetId,

    // Green multi-sig backend
    pub service_pubkey: &'static str,
    pub service_chain_code: &'static str,

    pub known_assets: KnownAssetIds,
}

pub const NETWORK_LIQUID: NetworkData = NetworkData {
    name: "Liquid",
    elements_params: &elements::address::AddressParams::LIQUID,
    bitcoin_network: bitcoin::Network::Bitcoin,
    account_path_sh_wpkh: [0x80000031, 0x800006F0, 0x80000000],
    account_path_wpkh: [0x80000054, 0x800006F0, 0x80000000],
    electrum_url: "blockstream.info:995",
    electrum_tls: true,
    asset_registry_url: "https://assets.blockstream.info",
    tx_explorer_url: "https://blockstream.info/liquid/tx/",
    address_explorer_url: "https://blockstream.info/address/",
    policy_asset: const_asset_id(
        "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
    ),

    service_chain_code: "02721cc509aa0c2f4a90628e9da0391b196abeabc6393ed4789dd6222c43c489",
    service_pubkey: "02c408c3bb8a3d526103fb93246f54897bdd997904d3e18295b49a26965cb41b7f",

    known_assets: KnownAssetIds {
        USDt: const_asset_id("ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2"),
        EURx: const_asset_id("18729918ab4bca843656f08d4dd877bed6641fbd596a0a963abbf199cfeb3cec"),
        MEX: const_asset_id("26ac924263ba547b706251635550a8649545ee5c074fe5db8d7140557baaf32e"),
        DePix: const_asset_id("02f22f8d9c76ab41661a2729e4752e2c5d1a263012141b86ea98af5472df5189"),
        SSWP: const_asset_id("06d1085d6a3a1328fb8189d106c7a8afbef3d327e34504828c4cac2c74ac0802"),
    },
};

pub const NETWORK_LIQUID_TESTNET: NetworkData = NetworkData {
    name: "LiquidTestnet",
    elements_params: &elements::address::AddressParams::LIQUID_TESTNET,
    bitcoin_network: bitcoin::Network::Testnet,
    account_path_sh_wpkh: [0x80000031, 0x80000001, 0x80000000],
    account_path_wpkh: [0x80000054, 0x80000001, 0x80000000],
    electrum_url: "blockstream.info:465",
    electrum_tls: true,
    asset_registry_url: "https://assets-testnet.blockstream.info",
    tx_explorer_url: "https://blockstream.info/liquidtestnet/liquidtestnet/tx/",
    address_explorer_url: "https://blockstream.info/liquidtestnet/address/",
    policy_asset: const_asset_id(
        "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
    ),

    service_chain_code: "c660eec6d9c536f4121854146da22e02d4c91d72af004d41729b9a592f0788e5",
    service_pubkey: "02c47d84a5b256ee3c29df89642d14b6ed73d17a2b8af0aca18f6f1900f1633533",

    known_assets: KnownAssetIds {
        USDt: const_asset_id("b612eb46313a2cd6ebabd8b7a8eed5696e29898b87a43bff41c94f51acef9d73"),
        EURx: const_asset_id("58af36e1b529b42f3e4ccce812924380058cae18b2ad26c89805813a9db25980"),
        MEX: const_asset_id("485ff8a902ad063bd8886ef8cfc0d22a068d14dcbe6ae06cf3f904dc581fbd2b"),
        DePix: const_asset_id("a5de979bc31dc731fa94b3661ae19c1e20cd067642c69798cad9011094a26f60"),

        SSWP: const_asset_id("1f9f9319beeded3aa3751190ec9b2d77df570c3b9e6e84a4aa321c11331e0118"),
    },
};

pub const NETWORK_LIQUID_REGTEST: NetworkData = NetworkData {
    name: "LiquidRegtest",
    elements_params: &elements::address::AddressParams::ELEMENTS,
    bitcoin_network: bitcoin::Network::Regtest,
    account_path_sh_wpkh: [0x80000031, 0x80000001, 0x80000000],
    account_path_wpkh: [0x80000054, 0x80000001, 0x80000000],
    electrum_url: "127.0.0.1:56705",
    electrum_tls: true,
    asset_registry_url: "",
    tx_explorer_url: "",
    address_explorer_url: "",
    policy_asset: const_asset_id(
        "2184a905372defaf7b0f506c01a54f734f7c0d0d60bbd1c2d90896a9438c1b76",
    ),

    service_chain_code: "",
    service_pubkey: "",

    known_assets: KnownAssetIds {
        USDt: const_asset_id("dd7fc500fbb8527cfa188cfb6e1a76194edc2884f779f63bfa3ccb2fea0b697e"),
        EURx: const_asset_id("aa176592c33bb4fd51ca6afbdd1ee89c2e8ead2dd022d9850642c19efec60d75"),
        MEX: const_asset_id("371e7b3735b85f29c54dafea13147fb59cd68994d09b1da286d983681e6e9e69"),
        DePix: const_asset_id("715bacc1a613952abf67569f3adb19172fef466f8d501ca319ff100c63899de4"),

        SSWP: const_asset_id("e3c747d55d55e0a06a392a0063d3626a5e93bf6a216eff1b655251bed1f09c9a"),
    },
};

impl Network {
    pub fn d(&self) -> &'static NetworkData {
        match *self {
            Network::Liquid => &NETWORK_LIQUID,
            Network::LiquidTestnet => &NETWORK_LIQUID_TESTNET,
            Network::Regtest => &NETWORK_LIQUID_REGTEST,
        }
    }
}

use super::*;

#[test]
fn utxos_parse() {
    let utxos = r#"[
    {
        "txid": "33ad18bc22932b3106038bba00e5070736ce66788062a76646c538cb96f74614",
        "vout": 3,
        "address": "tex1q8m8fxt6vw0pyaxsula82re8ezps30n0028v224",
        "label": "",
        "scriptPubKey": "00143ece932f4c73c24e9a1cff4ea1e4f9106117cdef",
        "amount": 0.00059012,
        "assetcommitment": "0ac0417fbca9a1076235b88034d9ec9628ca396962d7363de13147b7e28f4fb07e",
        "asset": "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
        "amountcommitment": "099fe5c1a6f23c28d5601f724843eb32478ca7f5531baed161e9140887a1dc1705",
        "amountblinder": "842dee70670e05c9371b9f93c206b5a1187bbdc4efe69691358ef9608b8a14fb",
        "assetblinder": "6fd47a1bce4edffe228f94129756d3b81421bd0f6c1fc27e4888d85d12292121",
        "confirmations": 23286,
        "spendable": true,
        "solvable": true,
        "desc": "wpkh([930f584f/84'/1'/0'/0/23]0379a1543ca47b1fcbde060147704cba606bd9177c628ff24b96e481c46d347e68)#0a5n6pef",
        "safe": true
    },
    {
        "txid": "ccdd0440e5576e47bf1c995ac326e8aed898da407a37f7b15c1dd4de1590f310",
        "vout": 0,
        "address": "8sXzk5zLBNX6meWB4vh6W57V13Bph3DUfK",
        "label": "",
        "redeemScript": "0014049a024a146e22788094e6ae420141788dda54fd",
        "scriptPubKey": "a9148fd6099e340a09a7876f681b6b36f8d11f01982487",
        "amount": 300.00000000,
        "assetcommitment": "0af0a4b072166baf78ea00767ca9c0ab9f8d3ce49293dc0aef269d5c0b02e5ea4c",
        "asset": "485ff8a902ad063bd8886ef8cfc0d22a068d14dcbe6ae06cf3f904dc581fbd2b",
        "amountcommitment": "08edf01dfeb235560576070a240fe6851a6b9e84f49114a59a02921d6163f40f17",
        "amountblinder": "a758533351f39ec4a9ef38e6d1eb9caf6587b682aad2a81afb5078df37bc3b13",
        "assetblinder": "21f20544f580685ea00f793f65f76b6e750666b9fbb2107a87b82bf5704bbe8e",
        "confirmations": 665803,
        "spendable": true,
        "solvable": true,
        "desc": "sh(wpkh([d8bb7596/0'/0'/9821']03a410a9b6f50ce0f3c717e9277f5241b53efde35a060dac093768d62292c03014))#fv63wk64",
        "safe": true
    },
    {
        "txid": "ccdd0440e5576e47bf1c995ac326e8aed898da407a37f7b15c1dd4de1590f310",
        "vout": 0,
        "address": "Pz1twbfkGG61KL1kNuhRDXpmyEyNzLPPWn",
        "label": "",
        "scriptPubKey": "76a9141e2b07399b2b08f94782dd398c7b8c6c477f7e8388ac",
        "amount": 0.00000005,
        "assetcommitment": "0ad02399d21760c660f2a28416304a9eba2bc77289ced672bd125864b256dc3677",
        "asset": "b8f3e0de9a68ce3f63d2b9656f9c954f8343ee7e02d688a6271d713eaf80b4fc",
        "amountcommitment": "089f523d901b1998f8f433b693ce361cf3bbe08e8f509091448b763548ace0a67d",
        "amountblinder": "3b1c1d84b02d3b8a17f889b7ef86f546e0e0b14700dd4a57f8807a5694af8ed8",
        "assetblinder": "876cac14bb2dd7d37d018dcea24476dee5b33169d60bbcc10098179b628c8cd7",
        "confirmations": 0,
        "spendable": true,
        "solvable": true,
        "desc": "pkh([d8bb7596/0'/0'/9821']03a410a9b6f50ce0f3c717e9277f5241b53efde35a060dac093768d62292c03014))#fv63wk64",
        "safe": true
    }
    ]"#;

    let utxos = serde_json::from_str::<ListUnspent>(&utxos).unwrap();

    assert!(utxos[0].is_segwit_v0());
    assert!(utxos[1].is_segwit_v0());
    assert!(!utxos[2].is_segwit_v0());
}

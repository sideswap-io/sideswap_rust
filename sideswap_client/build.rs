fn main() {
    let proto_path = "proto/sideswap.proto";
    let mut config = prost_build::Config::new();
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config
        .compile_protos(&[proto_path], &["../../ffi"])
        .unwrap();
    println!("cargo:rerun-if-changed={}", proto_path);

    vergen::vergen(vergen::Config::default()).unwrap();
}

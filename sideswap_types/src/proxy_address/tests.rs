use super::*;

#[test]
fn parse_numeric_variants() {
    let a: ProxyAddress = "socks5://127.0.0.1:9050".parse().unwrap();
    let b: ProxyAddress = "socks://127.0.0.1:9050".parse().unwrap();
    let c: ProxyAddress = "127.0.0.1:9050".parse().unwrap();
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn ipv6_and_display() {
    let p: ProxyAddress = "[::1]:9050".parse().unwrap();
    assert_eq!(p.to_string(), "socks5://[::1]:9050");
}

#[test]
fn rejects_credentials() {
    assert!("socks5://user@host:1080".parse::<ProxyAddress>().is_err());
}

#[test]
fn localhost() {
    let p: ProxyAddress = "localhost:9050".parse().unwrap();
    match p {
        ProxyAddress::Socks5 { address } => {
            assert!(address.ip().is_loopback());
            assert_eq!(address.port(), 9050);
        }
    }
}

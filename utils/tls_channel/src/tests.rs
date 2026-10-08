use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::{AllowedClients, Config, Error, PublicKey, SecretKey, Server, connect};

/// Binds a server that accepts every client.
async fn bind(server_key: &SecretKey, config: Config) -> Server {
    struct AcceptAll;
    impl crate::IsClientValid for AcceptAll {
        fn is_client_valid(&self, _public_key: &PublicKey) -> bool {
            true
        }
    }
    Server::bind(server_key, "127.0.0.1:0", config, Arc::new(AcceptAll))
        .await
        .unwrap()
}

fn big_config() -> Config {
    Config {
        max_packet_size: crate::MAX_PACKET_SIZE,
        ..Config::default()
    }
}

#[tokio::test]
async fn roundtrip_both_directions() {
    let server_key = SecretKey::generate();
    let client_key = SecretKey::generate();
    let client_pub = client_key.public_key();
    let server = bind(&server_key, Config::default()).await;
    let addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let mut channel = incoming.handshake().await.unwrap();
        assert_eq!(channel.peer_public_key(), client_pub);
        assert_eq!(channel.recv().await.unwrap(), &b"hello"[..]);
        assert_eq!(channel.recv().await.unwrap(), &b""[..]);
        channel.send(&b"world"[..]).await.unwrap();
        channel.send(vec![7u8; 1000]).await.unwrap();
        // Peer sends close_notify, we must see a clean EOF.
        assert!(matches!(channel.recv().await, Err(Error::Closed)));
    });

    let mut channel = connect(
        &client_key,
        server_key.public_key(),
        addr,
        Config::default(),
    )
    .await
    .unwrap();
    assert_eq!(channel.peer_public_key(), server_key.public_key());
    channel.send(&b"hello"[..]).await.unwrap();
    channel.send(Bytes::new()).await.unwrap();
    assert_eq!(channel.recv().await.unwrap(), &b"world"[..]);
    assert_eq!(channel.recv().await.unwrap(), vec![7u8; 1000]);
    channel.shutdown().await.unwrap();

    server_task.await.unwrap();
}

#[tokio::test]
async fn split_allows_concurrent_send_and_recv() {
    let server_key = SecretKey::generate();
    let server = bind(&server_key, Config::default()).await;
    let addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let channel = server.accept().await.unwrap().handshake().await.unwrap();
        let (mut reader, mut writer) = channel.split();
        let send = tokio::spawn(async move {
            for i in 0..100u32 {
                writer.send(i.to_le_bytes().to_vec()).await.unwrap();
            }
        });
        for i in 0..100u32 {
            assert_eq!(reader.recv().await.unwrap(), &i.to_le_bytes()[..]);
        }
        send.await.unwrap();
    });

    let channel = connect(
        &SecretKey::generate(),
        server_key.public_key(),
        addr,
        Config::default(),
    )
    .await
    .unwrap();
    let (mut reader, mut writer) = channel.split();
    for i in 0..100u32 {
        writer.send(i.to_le_bytes().to_vec()).await.unwrap();
    }
    for i in 0..100u32 {
        assert_eq!(reader.recv().await.unwrap(), &i.to_le_bytes()[..]);
    }
    server_task.await.unwrap();
}

#[tokio::test]
async fn wrong_server_key_fails_handshake() {
    let server_key = SecretKey::generate();
    let server = bind(&server_key, Config::default()).await;
    let addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        incoming.handshake().await.err().unwrap()
    });

    let wrong_key = SecretKey::generate().public_key();
    let err = connect(&SecretKey::generate(), wrong_key, addr, Config::default())
        .await
        .err()
        .unwrap();
    // Our verifier reports a key mismatch as `UnknownIssuer`.
    assert!(
        matches!(
            err,
            Error::Tls(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            ))
        ),
        "{err:?}"
    );
    // The server sees the client's alert or the closed socket.
    let err = server_task.await.unwrap();
    assert!(matches!(err, Error::Tls(_) | Error::Io(_)), "{err:?}");
}

#[tokio::test]
async fn unknown_client_is_rejected_during_handshake() {
    let server_key = SecretKey::generate();
    let allowed_key = SecretKey::generate();
    let unknown_key = SecretKey::generate();
    let allowed = Arc::new(AllowedClients::new());
    assert!(allowed.add(allowed_key.public_key()));
    assert!(!allowed.add(allowed_key.public_key()));
    let server = Server::bind(
        &server_key,
        "127.0.0.1:0",
        Config::default(),
        allowed.clone(),
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();

    let allowed_pub = allowed_key.public_key();
    let unknown_pub = unknown_key.public_key();
    let server_task = tokio::spawn(async move {
        // Unknown client: no channel, and the server learns which key tried.
        let err = server
            .accept()
            .await
            .unwrap()
            .handshake()
            .await
            .err()
            .unwrap();
        assert!(
            matches!(err, Error::ClientRejected { public_key } if public_key == unknown_pub),
            "{err:?}"
        );
        // Allowed client gets through.
        let channel = server.accept().await.unwrap().handshake().await.unwrap();
        assert_eq!(channel.peer_public_key(), allowed_pub);
        // Removing the key takes effect for the next connection.
        assert!(allowed.remove(&allowed_pub));
        let err = server
            .accept()
            .await
            .unwrap()
            .handshake()
            .await
            .err()
            .unwrap();
        assert!(matches!(err, Error::ClientRejected { .. }), "{err:?}");
    });

    let server_pub = server_key.public_key();
    // TLS 1.3 clients finish before the server verifies them, so the
    // rejection shows up as a TLS alert on the first read.
    let mut rejected = connect(&unknown_key, server_pub, addr, Config::default())
        .await
        .unwrap();
    let err = rejected.recv().await.err().unwrap();
    assert!(
        matches!(
            err,
            Error::Tls(rustls::Error::AlertReceived(_)) | Error::Io(_)
        ),
        "{err:?}"
    );

    let _channel = connect(&allowed_key, server_pub, addr, Config::default())
        .await
        .unwrap();

    let mut rejected = connect(&allowed_key, server_pub, addr, Config::default())
        .await
        .unwrap();
    assert!(rejected.recv().await.is_err());
    server_task.await.unwrap();
}

#[tokio::test]
async fn packet_size_limits_are_enforced_on_both_sides() {
    let server_key = SecretKey::generate();
    let server_config = Config {
        max_packet_size: 16,
        ..Config::default()
    };
    let client_config = Config {
        max_packet_size: 1024,
        ..Config::default()
    };
    let server = bind(&server_key, server_config).await;
    let addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let mut channel = server.accept().await.unwrap().handshake().await.unwrap();
        assert_eq!(channel.recv().await.unwrap(), &[1u8; 16][..]);
        let err = channel.recv().await.err().unwrap();
        assert!(
            matches!(err, Error::PacketTooLarge { limit: 16 }),
            "{err:?}"
        );
        let err = channel.send(vec![0u8; 17]).await.err().unwrap();
        assert!(matches!(err, Error::PacketTooLarge { limit: 16 }));
    });

    let mut channel = connect(
        &SecretKey::generate(),
        server_key.public_key(),
        addr,
        client_config,
    )
    .await
    .unwrap();
    let err = channel.send(vec![0u8; 1025]).await.err().unwrap();
    assert!(matches!(err, Error::PacketTooLarge { limit: 1024 }));
    channel.send(vec![1u8; 16]).await.unwrap();
    channel.send(vec![2u8; 17]).await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn large_packet_roundtrip() {
    let server_key = SecretKey::generate();
    let server = bind(&server_key, big_config()).await;
    let addr = server.local_addr().unwrap();
    let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let mut channel = server.accept().await.unwrap().handshake().await.unwrap();
        let received = channel.recv().await.unwrap();
        assert!(received == expected);
        channel.send(received).await.unwrap();
    });

    let mut channel = connect(
        &SecretKey::generate(),
        server_key.public_key(),
        addr,
        big_config(),
    )
    .await
    .unwrap();
    channel.send(payload.clone()).await.unwrap();
    assert!(channel.recv().await.unwrap() == payload);
    server_task.await.unwrap();
}

#[tokio::test]
async fn handshake_times_out_on_silent_client() {
    let server_key = SecretKey::generate();
    let config = Config {
        timeout: Duration::from_millis(200),
        ..Config::default()
    };
    let server = bind(&server_key, config).await;
    let addr = server.local_addr().unwrap();

    let _silent = TcpStream::connect(addr).await.unwrap();
    let err = server
        .accept()
        .await
        .unwrap()
        .handshake()
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::Timeout(_)), "{err:?}");
}

#[tokio::test]
async fn garbage_from_client_is_rejected() {
    let server_key = SecretKey::generate();
    let server = bind(&server_key, Config::default()).await;
    let addr = server.local_addr().unwrap();

    let mut garbage = TcpStream::connect(addr).await.unwrap();
    garbage.write_all(&[0x42u8; 64]).await.unwrap();
    let err = server
        .accept()
        .await
        .unwrap()
        .handshake()
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::Tls(_) | Error::Io(_)), "{err:?}");
}

#[tokio::test]
async fn config_is_validated() {
    let key = SecretKey::generate();
    let too_big = Config {
        max_packet_size: crate::MAX_PACKET_SIZE + 1,
        ..Config::default()
    };
    assert!(matches!(
        Server::bind(
            &key,
            "127.0.0.1:0",
            too_big.clone(),
            Arc::new(AllowedClients::new())
        )
        .await,
        Err(Error::InvalidConfig(_))
    ));
    let addr = "127.0.0.1:1".parse().unwrap();
    assert!(matches!(
        connect(&key, key.public_key(), addr, too_big).await,
        Err(Error::InvalidConfig(_))
    ));
}

#[test]
fn key_encodings_roundtrip() {
    let key = SecretKey::generate();
    let pk = key.public_key();
    let parsed: PublicKey = pk.to_string().parse().unwrap();
    assert_eq!(parsed, pk);
    assert_eq!(SecretKey::from_bytes(key.to_bytes()).public_key(), pk);
    assert_eq!(PublicKey::from_spki_der(&pk.spki_der()), Some(pk));
    assert_eq!(PublicKey::from_spki_der(&pk.spki_der()[1..]), None);

    // The PKCS#8 encoding must be accepted by ring and yield the same public key.
    let pair =
        ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&key.pkcs8_der()).unwrap();
    assert_eq!(
        ring::signature::KeyPair::public_key(&pair).as_ref(),
        pk.as_bytes()
    );
}

#[tokio::test]
async fn recv_is_cancel_safe() {
    let server_key = SecretKey::generate();
    let server = bind(&server_key, big_config()).await;
    let addr = server.local_addr().unwrap();
    let payload: Vec<u8> = (0..16 * 1024 * 1024).map(|i| (i % 253) as u8).collect();

    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let mut channel = server.accept().await.unwrap().handshake().await.unwrap();
        // Big frame first, then a small one. Cancel `recv` repeatedly while
        // the big frame is arriving in pieces.
        let mut cancelled = 0;
        let received = loop {
            match tokio::time::timeout(Duration::from_millis(1), channel.recv()).await {
                Ok(result) => break result.unwrap(),
                Err(_) => cancelled += 1,
            }
        };
        assert!(received == expected);
        assert!(cancelled > 0, "test did not exercise cancellation");
        assert_eq!(channel.recv().await.unwrap(), &b"after"[..]);
    });

    let mut channel = connect(
        &SecretKey::generate(),
        server_key.public_key(),
        addr,
        big_config(),
    )
    .await
    .unwrap();
    channel.send(payload).await.unwrap();
    channel.send(&b"after"[..]).await.unwrap();
    server_task.await.unwrap();
}

#[tokio::test]
async fn send_is_cancel_safe() {
    let server_key = SecretKey::generate();
    let server = bind(&server_key, big_config()).await;
    let addr = server.local_addr().unwrap();
    let payload: Vec<u8> = (0..16 * 1024 * 1024).map(|i| (i % 249) as u8).collect();

    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let mut channel = server.accept().await.unwrap().handshake().await.unwrap();
        assert!(channel.recv().await.unwrap() == expected);
        assert_eq!(channel.recv().await.unwrap(), &b"after"[..]);
        assert!(matches!(channel.recv().await, Err(Error::Closed)));
    });

    let mut channel = connect(
        &SecretKey::generate(),
        server_key.public_key(),
        addr,
        big_config(),
    )
    .await
    .unwrap();
    // Cancel the big send at least once, then send a small packet. The peer
    // must still receive the big packet intact before the small one.
    let cancelled = tokio::time::timeout(Duration::from_millis(1), channel.send(payload))
        .await
        .is_err();
    assert!(cancelled, "test did not exercise cancellation");
    channel.send(&b"after"[..]).await.unwrap();
    channel.shutdown().await.unwrap();
    server_task.await.unwrap();
}
